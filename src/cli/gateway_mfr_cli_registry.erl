-module(gateway_mfr_cli_registry).

-define(CLI_MODULES, [
                      gateway_config_cli_ecc
                     ]).

-export([register_cli/0, command/1]).

register_cli() ->
    clique:register(?CLI_MODULES).

command(Cmd) ->
    clique:run(Cmd).
