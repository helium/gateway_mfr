-module(gateway_mfr_cli_tpm).

-behavior(clique_handler).

-export([register_cli/0]).

register_cli() ->
    register_all_usage(),
    register_all_cmds().

register_all_usage() ->
    lists:foreach(fun(Args) ->
        apply(clique, register_usage, Args)
                  end,
        [
            tpm_usage(),
            tpm_test_usage(),
            tpm_provision_usage(),
            tpm_onboarding_usage()
        ]).

register_all_cmds() ->
    lists:foreach(fun(Cmds) ->
        [apply(clique, register_command, Cmd) || Cmd <- Cmds]
                  end,
        [
            tpm_cmd(),
            tpm_test_cmd(),
            tpm_provision_cmd(),
            tpm_onboarding_cmd()
        ]).

%%
%% tpm
%%

tpm_usage() ->
    [["tpm"],
        ["TPM commands\n\n",
            "  test - test.\n"
            "  provision - provision.\n"
            "  onboarding - onboarding.\n"
        ]
    ].

tpm_cmd() ->
    [
        [["tpm"], [], [], fun(_, _, _) -> usage end]
    ].

%%
%% tpm test
%%

tpm_test_cmd() ->
    [
        [["tpm", "test"], [], [], fun tpm_test/3]
    ].

tpm_test_usage() ->
    [["tpm", "test"],
        ["tpm test \n\n",
            "  Tests the attached TPM for correct shipment configuration.\n"
        ]
    ].

tpm_test_results() ->
    TestResults = gateway_mfr_worker:tpm_test(),
    FormatResult = fun({Name, Result}) ->
        [{name, Name}, {result, Result}]
                   end,
    Status = case lists:all(fun({_, S}) -> S == ok end, TestResults) of
                 true -> 0;
                 _ -> 1
             end,
    {Status, FormatResult, TestResults}.

tpm_test(["tpm", "test"], [], []) ->
    {Status, FormatResult, TestResults} = tpm_test_results(),
    {exit_status, Status, [clique_status:table(lists:map(FormatResult, TestResults))]};
tpm_test([_, _, _], [], []) ->
    usage.

%%
%% tpm provision
%%

tpm_provision_cmd() ->
    [
        [["tpm", "provision"], [],
            [],
            fun tpm_provision/3]
    ].

tpm_provision_usage() ->
    [["tpm", "provision"],
        ["tpm provision \n\n",
            "  Provision the TPM chip on the hotspot for production use.\n"
            "  This prints out the public key which can be used as the onboarding key.\n\n"
        ]
    ].

tpm_provision(["tpm", "provision"], [], []) ->
    case gateway_mfr_worker:tpm_provision() of
        {ok, B58Key} ->
            {Status, FormatResult, TestResults} = tpm_test_results(),
            {exit_status, Status, [clique_status:text(B58Key), clique_status:table(lists:map(FormatResult, TestResults))]};
        {error, Error} ->
            Msg = io_lib:format("~p", [Error]),
            {Status, FormatResult, TestResults} = tpm_test_results(),
            {exit_status, Status, [clique_status:alert([clique_status:text(Msg), clique_status:table(lists:map(FormatResult, TestResults))])]}
    end;
tpm_provision([_, _], [], []) ->
    usage.


%%
%% tpm onboarding
%%


tpm_onboarding_cmd() ->
    [
        [["tpm", "onboarding"], [],
            [],
            fun tpm_onboarding/3]
    ].

tpm_onboarding_usage() ->
    [["tpm", "onboarding"],
        ["tpm onboarding \n\n",
            "  Retrieves the onboarding/miner key of a provisioned TPM.\n"
        ]
    ].

tpm_onboarding(["tpm", "onboarding"], [], []) ->
    case gateway_mfr_worker:tpm_miner() of
        {ok, B58Key} ->
            [clique_status:text(B58Key)];
        {error, Error} ->
            Msg = io_lib:format("~p", [Error]),
            {exit_status, 1, [clique_status:alert([clique_status:text(Msg)])]}
    end;
tpm_onboarding([_, _], [], []) ->
    usage.

