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
         ecc_test/0,
         ecc_onboarding/0]).


-define(ONBOARDING_SLOT, 15).

-record(state, {
                ecc_handle :: pid()
               }).


ecc_provision() ->
    gen_server:call(?WORKER, ecc_provision).

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
    %% Generate key slot 15 and lock the slot
    ok = gen_compact_key(Pid, ?ONBOARDING_SLOT, 3),
    ok = ecc508:lock(Pid, {slot, ?ONBOARDING_SLOT}),
    ecc508:idle(Pid),
    handle_onboarding_key(State).

handle_onboarding_key(#state{ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    {ok, PubKey} = ecc508:genkey(Pid, public, ?ONBOARDING_SLOT),
    case ecc_compact:is_compact(PubKey) of
        {true, CompactKey} ->
            B58PubKey = base58check_encode(16#00, <<0:8, CompactKey/binary>>),
            {ok, B58PubKey};
        false ->
            {error, not_compact}
    end.


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
handle_test(#state{ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    lists:map(fun({Key, Fun}) ->
                      {Key, Fun(Pid)}
                end, [
                      {serial_num, fun check_serial/1},
                      {config_zone_lock, fun check_zone_config_lock/1},
                      {data_zone_lock, fun check_zone_data_lock/1},
                      {slot_config, fun check_slot_configuration/1},
                      {key_config, fun check_key_configuration/1},
                      {onboarding_key, fun check_onboarding_key/1}
                     ]).

check_serial(Pid) ->
    case ecc508:serial_num(Pid) of
        {ok, <<16#01, 16#23, _:6/binary, 16#EE>>} ->
            ok;
        {ok, Other} ->
            {error, {unexpected_serial, Other}};
        {error, Error} ->
            {error, Error}
    end.

check_zone_config_lock(Pid) ->
    case ecc508:get_locked(Pid , config) of
        {ok, true} -> ok;
        {ok, false} -> {error, unlocked};
        {error, Error} -> {error, Error}
    end.


check_zone_data_lock(Pid) ->
    case ecc508:get_locked(Pid, data) of
        {ok, true} -> ok;
        {ok, false} -> {error, unlocked};
        {error, Error} -> {error, Error}
    end.

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

check_key_configuration(Pid) ->
    ECCKeyConfig = ecc508:ecc_key_config(),
    lists:foldl(fun(Slot, ok) ->
                        case ecc508:get_key_config(Pid, Slot) of
                            {ok, ECCKeyConfig} ->
                                ok;
                            {ok, Other} ->
                                {error, {invalid_key_config, Slot, Other}};
                            {error, Error} ->
                                {error, Error}
                        end;
                   (_Slot, Error) ->
                        Error
                end, ok, lists:seq(0, 15)).


check_onboarding_key(Pid) ->
    case {ecc508:get_slot_locked(Pid, ?ONBOARDING_SLOT),
          ecc508:genkey(Pid, public, ?ONBOARDING_SLOT)} of
        {true, {ok, PubKey}} ->
            case ecc_compact:is_compact(PubKey) of
                {true, _} -> ok;
                false -> {error, key_not_compact}
            end;
        {false, _} ->
            {error, onboarding_slot_unlocked};
        {_, {error, Error}} ->
            {error, {no_onboarding_key, Error}}
    end.


%%
%% Utilities
%%

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
