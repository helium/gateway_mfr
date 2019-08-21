-module(gateway_mfr_worker).

-behavior(gen_server).

-define(WORKER, gateway_mfr).

%% gen_server
-export([start_link/0,
         init/1,
         handle_call/3,
         handle_cast/2,
         terminate/2]).
%% api
-export([ecc_provision/0,
         ecc_provision_onboard/0,
         ecc_test/0,
         ecc_onboarding/0]).


-define(ONBOARDING_SLOT, 15).

-record(state, {
                ecc_handle :: pid()
               }).


ecc_provision() ->
    gen_server:call(?WORKER, ecc_provision).

ecc_provision_onboard() ->
    gen_server:call(?WORKER, ecc_provision_onboard).

ecc_test() ->
    gen_server:call(?WORKER, ecc_test).

ecc_onboarding() ->
    gen_server:call(?WORKER, ecc_onboarding).



%% gen_server

start_link() ->
    gen_server:start_link({local, ?WORKER}, ?MODULE, [], []).


init(_) ->
    {ok, ECCHandle} = ecc508:start_link(),
    {ok, #state{ecc_handle=ECCHandle}}.


handle_call(ecc_provision, _From, State=#state{}) ->
    case can_provision(State) of
        ok -> {reply, handle_provision(State), State};
        {error, Error} -> {reply, {error, Error}, State}
    end;
handle_call(ecc_provision_onboard, _From, State=#state{}) ->
    {reply, handle_provision_onboard(State), State};
handle_call(ecc_test, _From, State=#state{}) ->
    {reply, handle_test(State), State};
handle_call(ecc_onboarding, _From, State=#state{}) ->
    {reply, handle_onboarding_key(State), State};
handle_call(Msg, _From, State=#state{}) ->
    lager:warning("Unhandled call ~p", [Msg]),
    {reply, ok, State}.


handle_cast(Msg, State=#state{}) ->
    lager:warning("Unhandled cast ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, #state{ecc_handle=ECCHandle}) ->
    catch ecc508:stop(ECCHandle).

%%
%% Internal
%%

-spec can_provision(#state{}) -> ok | {error, term()}.
can_provision(#state{ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    case {ecc508:get_locked(Pid, config), ecc508:get_locked(Pid, data)} of
        {{ok, false}, {ok, false}} ->
            ok;
        {{ok, ConfigLocked}, {ok, DataLocked}} ->
            {error, {zone_locked, [{config, ConfigLocked},
                                   {data, DataLocked}]}}
    end.

%% Provisions the ECC to make it ready for our use.
%%
%% 1. Conifgure slots 0-14 for lockable ECC slots _with_ ECDH
%% operation
%%
%% 2. Configure slot 15 for ECC slot _without_ ECDH operation. This
%% slot is for the onboarding key.
%%
%% 3. Lock the configuration and data zones.
%%
%% 4. Generate onboarding key in slot 15 and lock the slot
%%
%% 5. Return the onboarding key in b58 encoded form the way
%% libp2p_crypto does
handle_provision(State=#state{ecc_handle=Pid}) ->
    ECCSlotConfig = ecc508:ecc_slot_config(),
    ECDHSlotConfig = ECCSlotConfig#{read_key => [ecdh_operation, internal_signatures, external_signatures]},
    ecc508:wake(Pid),
    %% Onboarding key does not have ecdh enabled
    ok = ecc508:set_slot_config(Pid, 15, ECCSlotConfig),
    lists:foreach(fun(Slot) ->
                          ok = ecc508:set_slot_config(Pid, Slot, ECDHSlotConfig)
                  end, lists:seq(0, 15) -- [?ONBOARDING_SLOT]),
    ecc508:idle(Pid),
    %% Configure key slots for private keys
    ECCKeyConfig = ecc508:ecc_key_config(),
    ecc508:wake(Pid),
    lists:foreach(fun(Slot) ->
                          ok = ecc508:set_key_config(Pid, Slot, ECCKeyConfig)
                  end, lists:seq(0, 15)),

    ecc508:wake(Pid),
    %% Lock data and config zones
    ecc508:lock(Pid, config),
    ecc508:lock(Pid, data),
    ecc508:idle(Pid),
    %% Generate key slot 15 and lock the slot
    ok = handle_provision_onboard(State),
    handle_onboarding_key(State).

-spec handle_provision_onboard(#state{}) -> ok | {error, term()}.
handle_provision_onboard(State=#state{ecc_handle=Pid}) ->
    Tests = run_tests([{zone_locked, config},
                       {zone_locked, data},
                       slot_config,
                       key_config,
                       {slot_unlocked, ?ONBOARDING_SLOT}
                      ], State),
    case lists:filter(fun({_, ok}) ->
                              false;
                         ({_, _}) ->
                              true
                      end, Tests) of
        [] ->
            %% No Failures, go generate and lock onboarding
            ecc508:wake(Pid),
            %% Generate ONBOARDING slot and lock the slot
            ok = gen_compact_key(Pid, ?ONBOARDING_SLOT),
            ok = ecc508:lock(Pid, {slot, ?ONBOARDING_SLOT}),
            ecc508:idle(Pid),
            ok;
        Failures ->
            {error, Failures}
    end.

-spec handle_onboarding_key(#state{}) -> {ok, string()} | {error, term()}.
handle_onboarding_key(#state{ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    case ecc508:genkey(Pid, public, ?ONBOARDING_SLOT) of
        {error, Error} ->
            {error, Error};
        {ok, PubKey} ->
            case ecc_compact:is_compact(PubKey) of
                {true, CompactKey} ->
                    B58PubKey = base58check_encode(16#00, <<0:8, CompactKey/binary>>),
                    {ok, B58PubKey};
                false ->
                    {error, not_compact}
            end
    end.

-spec run_tests([Test::term()], #state{}) -> [{Test::term(), ok | {error, term()}}].
run_tests(Tests, #state{ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    run_tests(Tests, Pid, []).

run_tests([], _, Acc) ->
    lists:reverse(Acc);
run_tests([serial_num=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_serial(Pid)} | Acc]);
run_tests([{zone_locked, Zone}=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_zone_locked(Zone, Pid)} | Acc]);
run_tests([slot_config=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_slot_configuration(Pid)} | Acc]);
run_tests([key_config=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_key_configuration(Pid)} | Acc]);
run_tests([onboarding_key=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_onboarding_key(Pid)} | Acc]);
run_tests([{slot_unlocked, Slot}=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_slot_unlocked(Slot, Pid)} | Acc]);
run_tests([{slot_locked, Slot}=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_slot_locked(Slot, Pid)} | Acc]).



%% Checking whether the ECC is ready for shipment means verifying
%% that:
%%
%% 1. it's available and version matches
%%
%% 2. The configuration and data zone are locked
%%
%% 3. The configuraiton slots are configured to be ECDH/ECC slots for
%% all but the onboarding slot which is ECC only
%%
%% 4. The key configuration is set to ecc key configuration for all
%% slots
%%
%% 5. The onboarding slot is locked and has a key in it.
%%
handle_test(State=#state{}) ->
    run_tests([serial_num,
               {zone_locked, config},
               {zone_locked, data},
               slot_config,
               key_config,
               onboarding_key,
               {slot_locked, ?ONBOARDING_SLOT}
              ], State).

-spec check_serial(pid()) -> ok | {error, term()}.
check_serial(Pid) ->
    case ecc508:serial_num(Pid) of
        {ok, <<16#01, 16#23, _:6/binary, 16#EE>>} ->
            ok;
        {ok, Other} ->
            {error, {unexpected_serial, Other}};
        {error, Error} ->
            {error, Error}
    end.

-spec check_zone_locked(config | data, pid()) -> ok | {error, term()}.
check_zone_locked(Zone, Pid) ->
    case ecc508:get_locked(Pid, Zone) of
        {ok, true} -> ok;
        {ok, false} -> {error, unlocked};
        {error, Error} -> {error, Error}
    end.

-spec check_slot_unlocked(non_neg_integer(), pid()) -> ok | {error, term()}.
check_slot_unlocked(Slot, Pid) ->
    case ecc508:get_slot_locked(Pid, Slot) of
        true -> {error, locked};
        false -> ok;
        {error, Error} -> {error, Error}
    end.

-spec check_slot_locked(non_neg_integer(), pid()) -> ok | {error, term()}.
check_slot_locked(Slot, Pid) ->
    case ecc508:get_slot_locked(Pid, Slot) of
        true -> ok;
        false -> {error, unlocked};
        {error, Error} -> {error, Error}
    end.

-spec check_slot_configuration(pid()) -> ok | {error, term()}.
check_slot_configuration(Pid) ->
    ECCConfig = ecc508:ecc_slot_config(),
    ECDHConfig = ECCConfig#{read_key =>
                                [ecdh_operation,
                                 internal_signatures,
                                 external_signatures]},
    lists:foldl(fun(Slot, ok) ->
                        case ecc508:get_slot_config(Pid, Slot) of
                            {ok, ECCConfig} when Slot == ?ONBOARDING_SLOT ->
                                ok;
                            {ok, ECDHConfig} when Slot /= ?ONBOARDING_SLOT ->
                                ok;
                            {ok, _Other} ->
                                {error, {invalid_slot_config, Slot}};
                            {error, Error} ->
                                {error, Error}
                        end;
                   (_Slot, Error) ->
                        Error
                end, ok, lists:seq(0, 15)).

-spec check_key_configuration(pid()) -> ok | {error, term()}.
check_key_configuration(Pid) ->
    ECCKeyConfig = ecc508:ecc_key_config(),
    lists:foldl(fun(Slot, ok) ->
                        case ecc508:get_key_config(Pid, Slot) of
                            {ok, ECCKeyConfig} ->
                                ok;
                            {ok, _Other} ->
                                {error, {invalid_key_config, Slot}};
                            {error, Error} ->
                                {error, Error}
                        end;
                   (_Slot, Error) ->
                        Error
                end, ok, lists:seq(0, 15)).


-spec check_onboarding_key(pid()) -> ok | {error, term()}.
check_onboarding_key(Pid) ->
    case ecc508:genkey(Pid, public, ?ONBOARDING_SLOT) of
        {ok, PubKey} ->
            case ecc_compact:is_compact(PubKey) of
                {true, _} -> ok;
                false -> {error, not_compact}
            end;
        {error, Error} ->
            {error, Error}
    end.


%%
%% Utilities
%%

gen_compact_key(Pid, Slot) ->
    gen_compact_key(Pid, Slot, 100).

gen_compact_key(_Pid, _Slot, 0) ->
    {error, compact_key_create_failed};
gen_compact_key(Pid, Slot, N) when N > 0 ->
    case  ecc508:genkey(Pid, private, Slot) of
        {ok, PubKey} ->
            case ecc_compact:is_compact(PubKey) of
                {true, _} -> ok;
                false -> gen_compact_key(Pid, Slot, N - 1)
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec base58check_encode(non_neg_integer(), binary()) -> string().
base58check_encode(Version, Payload) when Version >= 0, Version =< 16#FF ->
  VPayload = <<Version:8/unsigned-integer, Payload/binary>>,
  <<Checksum:4/binary, _/binary>> = crypto:hash(sha256, crypto:hash(sha256, VPayload)),
  Result = <<VPayload/binary, Checksum/binary>>,
  base58:binary_to_base58(Result).
