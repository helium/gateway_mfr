-module(gateway_mfr_worker).

-include_lib("public_key/include/public_key.hrl").

-behavior(gen_server).

-define(WORKER, gateway_mfr).

%% gen_server
-export([start_link/1,
         init/1,
         handle_call/3,
         handle_cast/2,
         terminate/2]).
%% api
-export([ecc_provision/0,
         ecc_provision_onboard/0,
         ecc_test/0,
         ecc_miner/0,
         tpm_provision/0,
         tpm_test/0,
         tpm_miner/0]).


-define(KEY_SLOT, 0).
-define(SRK_PATH, "HS/SRK").
-define(KEY_PATH, ?SRK_PATH++"/MinerKey").

-define(NOT_PROVISIONED, 16#60034).
-define(ESYS_TR_NONE, 16#fff).
-define(ESYS_TR_RH_OWNER, 16#101).
-define(ESYS_TR_PASSWORD, 16#0ff).
-define(TPM2_CAP_HANDLES, 16#1).
-define(TPM2_PERSISTENT_FIRST, 16#81000000).
-define(TPM2_MAX_CAP_HANDLES, 254).

-record(state, {
                crypto :: atom(),
                ecc_handle :: pid()
               }).


ecc_provision() ->
    gen_server:call(?WORKER, ecc_provision).

ecc_provision_onboard() ->
    gen_server:call(?WORKER, ecc_provision_onboard).

ecc_test() ->
    gen_server:call(?WORKER, ecc_test).

ecc_miner() ->
    gen_server:call(?WORKER, ecc_miner).

tpm_provision() ->
    gen_server:call(?WORKER, tpm_provision).

tpm_test() ->
    gen_server:call(?WORKER, tpm_test).

tpm_miner() ->
    gen_server:call(?WORKER, tpm_miner).


%% gen_server

start_link(Crypto) ->
    gen_server:start_link({local, ?WORKER}, ?MODULE, [Crypto], []).


init([Crypto]) ->
    case Crypto of
        ecc -> {ok, ECCHandle} = ecc508:start_link(),
               {ok, #state{crypto=ecc, ecc_handle=ECCHandle}};
        tpm -> erlfapi:initialize(null),
               {ok, #state{crypto=tpm}}
    end.


handle_call(ecc_provision, _From, State=#state{}) ->
    case can_provision(State) of
        ok -> {reply, handle_provision(State), State};
        {error, Error} -> {reply, {error, Error}, State}
    end;
handle_call(ecc_provision_onboard, _From, State=#state{}) ->
    {reply, handle_provision_miner_key(State), State};
handle_call(ecc_test, _From, State=#state{}) ->
    {reply, handle_test(State), State};
handle_call(ecc_miner, _From, State=#state{}) ->
    {reply, handle_miner_key(State), State};
handle_call(tpm_provision, _From, State=#state{}) ->
    case can_provision(State) of
        ok -> Result = case handle_provision(State) of
                           {error, _} -> clear_tpm(), handle_provision(State);
                           _Else -> _Else
                       end,
            {reply, Result, State};
        {error, provisioned} -> {reply, {error, already_provisioned}, State};
        {error, Error} -> {reply, {error, Error}, State}
    end;
handle_call(tpm_provision_onboard, _From, State=#state{}) ->
    {reply, handle_provision_miner_key(State), State};
handle_call(tpm_test, _From, State=#state{}) ->
    {reply, handle_test(State), State};
handle_call(tpm_miner, _From, State=#state{}) ->
    {reply, handle_miner_key(State), State};
handle_call(Msg, _From, State=#state{}) ->
    lager:warning("Unhandled call ~p", [Msg]),
    {reply, ok, State}.


handle_cast(Msg, State=#state{}) ->
    lager:warning("Unhandled cast ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, #state{crypto = ecc, ecc_handle=ECCHandle}) ->
    catch ecc508:stop(ECCHandle);

terminate(_Reason, #state{crypto = tpm}) ->
    erlfapi:finalize().

%%
%% Internal
%%

-spec can_provision(#state{}) -> ok | {error, term()}.
can_provision(#state{crypto=ecc, ecc_handle=Pid}) ->
    ecc508:wake(Pid),
        case {ecc508:get_locked(Pid, config), ecc508:get_locked(Pid, data)} of
            {{ok, false}, {ok, false}} ->
                ok;
            {{ok, ConfigLocked}, {ok, DataLocked}} ->
                {error, {zone_locked, [{config, ConfigLocked},
                                       {data, DataLocked}]}}
        end;

can_provision(#state{crypto=tpm}) ->
    case check_tpm_provision_state() of
        ok -> case check_tpm_key_path() of
                  ok -> case check_tpm_miner_key() of
                        ok -> {error, provisioned};
                        _Else -> ok
                        end;
                  _Else -> ok
              end;
        _Else -> ok
    end.

%% Provisions the ECC to make it ready for our use.
%%
%% 1. Conifgure slots 0-15 for lockable ECC slots _with_ ECDH
%% operation
%%
%% 2. Lock the configuration and data zones.
%%
%% 3. Generate miner key in slot 0
%%
%% 4. Return the miner key in b58 encoded form the way libp2p_crypto does
handle_provision(State=#state{crypto=ecc, ecc_handle=Pid}) ->
    ECCSlotConfig = ecc508:ecc_slot_config(),
    ECDHSlotConfig = ECCSlotConfig#{read_key => [ecdh_operation, internal_signatures, external_signatures]},
    ecc508:wake(Pid),
    lists:foreach(fun(Slot) ->
                          ok = ecc508:set_slot_config(Pid, Slot, ECDHSlotConfig)
                  end, lists:seq(0, 15)),
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
    %% Generate key slot 0
    ok = handle_provision_miner_key(State),
    handle_miner_key(State);

handle_provision(State=#state{crypto=tpm}) ->
    ProvisionStatus = case check_tpm_provision_state() of
        ok -> ok;
        _ -> erlfapi:provision("", null, "")
    end,

    CreateKeyStatus = case ProvisionStatus of
        ok -> case check_tpm_key_path() of
                  ok -> ok;
                  _ -> handle_provision_miner_key(State)
              end;
        _ -> {error, provision_error}
    end,

    KeyCompliance = case CreateKeyStatus of
        ok -> handle_miner_key(State);
        _ -> {error, key_error}
    end,

    case ProvisionStatus of
        ok -> case CreateKeyStatus of
                  ok -> KeyCompliance;
                  {error, RC} -> {error, erlfapi:rc_decode(RC)}
              end;
        {error, RC} -> {error, erlfapi:rc_decode(RC)}
    end.

clear_tpm() ->
    erlfapi:delete("HE"),
    erlfapi:delete("HN"),
    erlfapi:delete("LOCKOUT"),
    erlfapi:delete("HS"),

    {ok, TCTI} = erlfapi:get_tcti(),
    erlesys:initialize(TCTI),
    {ok, PersistentHandles} = erlesys:get_capability(?ESYS_TR_NONE, ?ESYS_TR_NONE, ?ESYS_TR_NONE, ?TPM2_CAP_HANDLES, ?TPM2_PERSISTENT_FIRST, ?TPM2_MAX_CAP_HANDLES),
    [evict_control(Handle) || Handle <- PersistentHandles],
    erlesys:finalize().


evict_control(Handle) ->
    {ok, TRHandle} = erlesys:tr_from_tpm_public(Handle, ?ESYS_TR_NONE, ?ESYS_TR_NONE, ?ESYS_TR_NONE),

    {ok, _} = erlesys:evict_control(?ESYS_TR_RH_OWNER, TRHandle, ?ESYS_TR_PASSWORD, ?ESYS_TR_NONE, ?ESYS_TR_NONE, ?TPM2_PERSISTENT_FIRST).

-spec handle_provision_miner_key(#state{}) -> ok | {error, term()}.
handle_provision_miner_key(State=#state{crypto=ecc, ecc_handle=Pid}) ->
    Tests = run_tests([{zone_locked, config},
                       {zone_locked, data},
                       slot_config,
                       key_config,
                       {slot_unlocked, ?KEY_SLOT}
                      ], State),
    case lists:filter(fun({_, ok}) ->
                              false;
                         ({_, _}) ->
                              true
                      end, Tests) of
        [] ->
            %% No Failures, go generate key
            ecc508:wake(Pid),
            %% Generate KEY slot. We currently do not lock the slot which 
            %% may allow key regeneration at some point
            ok = gen_compact_key(Pid, ?KEY_SLOT),
            ecc508:idle(Pid),
            ok;
        Failures ->
            {error, Failures}
    end;

handle_provision_miner_key(#state{crypto=tpm}) ->
    case gen_compact_key(?KEY_PATH) of
        ok -> ok;
        {error, ResponseCode} -> DecodedResponse = erlfapi:rc_decode(ResponseCode),
            {error, DecodedResponse}
    end.

-spec handle_miner_key(#state{}) -> {ok, string()} | {error, term()}.
handle_miner_key(#state{crypto=ecc, ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    case ecc508:genkey(Pid, public, ?KEY_SLOT) of
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
    end;

handle_miner_key(#state{crypto=tpm}) ->
    case erlfapi:get_public_key_ecc(?KEY_PATH) of
        {ok, PubPoint} ->
            PubKey = {#'ECPoint'{point=PubPoint}, {namedCurve, ?secp256r1}},
            case ecc_compact:is_compact(PubKey) of
                {true, CompactKey} -> B58PubKey = base58check_encode(16#00, <<0:8, CompactKey/binary>>),
                    {ok, B58PubKey};
                false -> {error, not_compact}
            end;
        _Else -> _Else
    end.

-spec run_tests([Test::term()], #state{}) -> [{Test::term(), ok | {error, term()}}].
run_tests(Tests, #state{crypto=ecc, ecc_handle=Pid}) ->
    ecc508:wake(Pid),
    run_tests(Tests, Pid, []);
run_tests(Tests, #state{crypto=tpm}) ->
    run_tests(Tests, []);
run_tests([], Acc) ->
    lists:reverse(Acc);
run_tests([tpm_provision_state=N | Tail], Acc) ->
    run_tests(Tail, [{N, check_tpm_provision_state()} | Acc]);
run_tests([tpm_key_path=N | Tail], Acc) ->
    run_tests(Tail, [{N, check_tpm_key_path()} | Acc]);
run_tests([tpm_miner_key=N | Tail], Acc) ->
    run_tests(Tail, [{N, check_tpm_miner_key()} | Acc]).

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
run_tests([miner_key=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_miner_key(Pid)} | Acc]);
run_tests([{slot_unlocked, Slot}=N | Tail], Pid, Acc) ->
    run_tests(Tail, Pid, [{N, check_slot_unlocked(Slot, Pid)} | Acc]).


%% Checking whether the ECC is ready for shipment means verifying
%% that:
%%
%% 1. it's available and version matches
%%
%% 2. The configuration and data zone are locked
%%
%% 3. The configuraiton slots are configured to be ECDH/ECC slots
%%
%% 4. The key configuration is set to ecc key configuration for all
%% slots
%%
%% 5. The miner key slot is locked and has a key in it.
%%
handle_test(State=#state{crypto=ecc}) ->
    run_tests([serial_num,
               {zone_locked, config},
               {zone_locked, data},
               slot_config,
               key_config,
               miner_key
              ], State);

%% Checking whether the TPM is ready for shipment means verifying
%% that:
%%
%% 1. fapi is provisioned
%%
%% 2. key is created
%%
%% 3. key has correct type
%%

handle_test(State=#state{crypto=tpm}) ->
    run_tests([tpm_provision_state, tpm_key_path, tpm_miner_key], State).

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

-spec check_slot_configuration(pid()) -> ok | {error, term()}.
check_slot_configuration(Pid) ->
    ECCConfig = ecc508:ecc_slot_config(),
    ECDHConfig = ECCConfig#{read_key =>
                                [ecdh_operation,
                                 internal_signatures,
                                 external_signatures]},
    lists:foldl(fun(Slot, ok) ->
                        case ecc508:get_slot_config(Pid, Slot) of
                            {ok, ECDHConfig} ->
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


-spec check_miner_key(pid()) -> ok | {error, term()}.
check_miner_key(Pid) ->
    case ecc508:genkey(Pid, public, ?KEY_SLOT) of
        {ok, PubKey} ->
            case ecc_compact:is_compact(PubKey) of
                {true, _} -> ok;
                false -> {error, not_compact}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec check_tpm_provision_state() -> ok | {error, term()}.
check_tpm_provision_state() ->
    case erlfapi:list(?SRK_PATH) of
        {ok, ObjectsString} -> case string:lexemes(ObjectsString, ":") of
                                   [] -> {error, not_provisioned};
                                   _ -> ok
                               end;
        {error, ?NOT_PROVISIONED} -> {error, not_provisioned};
        {error, Error} -> {error, erlfapi:rc_decode(Error)}
    end.
-spec check_tpm_key_path() -> ok | {error, term()}.
check_tpm_key_path() ->
    case erlfapi:list(?KEY_PATH) of
        {ok, ObjectsString} -> case string:lexemes(ObjectsString, ":") of
                                   [] -> {error, no_key};
                                   _ -> ok
                               end;
        {error, Error} -> {error, erlfapi:rc_decode(Error)}
    end.

-spec check_tpm_miner_key() -> ok | {error, term()}.
check_tpm_miner_key() ->
    case erlfapi:get_public_key_ecc(?KEY_PATH) of
        {ok, PubPoint} ->
            CompactKey = {#'ECPoint'{point=PubPoint}, {namedCurve, ?secp256r1}},
            case ecc_compact:is_compact(CompactKey) of
                {true, _} -> ok;
                false -> {error, not_compact}
            end;
        _Else -> _Else
    end.

%%
%% Utilities
%%

gen_compact_key(Path) ->
    gen_compact_key(Path, 100).

gen_compact_key(_Path, 0) ->
    {error, compact_key_create_failed};

gen_compact_key(Path, N) when N > 0 ->
    case erlfapi:create_key(Path, "noDa, sign, decrypt", "", "") of
        ok -> case erlfapi:get_public_key_ecc(Path) of
                  {ok, PubPoint} ->
                      CompactKey = {#'ECPoint'{point=PubPoint}, {namedCurve, ?secp256r1}},
                      case ecc_compact:is_compact(CompactKey) of
                          {true, _} -> ok;
                          false -> erlfapi:delete(Path), gen_compact_key(Path, N - 1)
                      end;
                  _Else -> _Else
              end;
        _Else -> _Else
    end;

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
