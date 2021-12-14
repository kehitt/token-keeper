-module(tk_token).

-export([child_specs/1]).
-export([verify/2]).
-export([issue/1]).

-callback child_spec(token_opts()) -> supervisor:child_spec().
-callback verify(token_string(), source_context()) -> {ok, token_data()} | {error, Reason :: _}.
-callback issue(token_data()) -> {ok, token_string()} | {error, Reason :: _}.

-type tokens_config() :: #{token_type() => token_opts()}.
-type token_opts() :: tk_token_jwt:opts().

-export_type([tokens_config/0]).

%%

-type token_string() :: binary().
-type token_data() :: #{
    id := token_id(),
    type := token_type(),
    expiration := expiration(),
    payload := payload(),
    authority_id := authority_id(),
    source_context => source_context()
}.

-type token_id() :: binary().
-type token_type() :: jwt | compact.
-type expiration() :: unlimited | non_neg_integer().
-type payload() :: map().
-type authority_id() :: tk_authdata:authority_id().
-type source_context() :: #{
    request_origin => binary()
}.

-export_type([token_string/0]).
-export_type([token_data/0]).

-export_type([token_id/0]).
-export_type([token_type/0]).
-export_type([expiration/0]).
-export_type([payload/0]).
-export_type([authority_id/0]).
-export_type([source_context/0]).

%%

-spec child_specs(tokens_config()) -> [supervisor:child_spec()].
child_specs(TokensOpts) ->
    maps:fold(
        fun(TokenType, TokenOpts, Acc) ->
            [child_spec(TokenType, TokenOpts) | Acc]
        end,
        [],
        TokensOpts
    ).

child_spec(TokenType, TokenOpts) ->
    Handler = get_token_handler(TokenType),
    Handler:child_spec(TokenOpts).

%%

-spec verify(token_string(), source_context()) -> {ok, token_data()} | {error, Reason :: _}.
verify(Token, SourceContext) ->
    case determine_token_type(Token) of
        {ok, KnownType} ->
            verify(KnownType, Token, SourceContext)
        % {error, unknown_token_type = Reason} ->
        %     {error, Reason}
    end.

-spec issue(token_data()) -> {ok, token_string()} | {error, Reason :: _}.
issue(#{type := TokenType} = TokenData) ->
    issue(TokenType, TokenData).

%%

determine_token_type(<<"tkc1:", _/binary>>) ->
    {ok, compact};
determine_token_type(_) ->
    {ok, jwt}.

verify(TokenType, Token, SourceContext) ->
    Handler = get_token_handler(TokenType),
    case Handler:verify(Token, SourceContext) of
        {ok, VerifiedToken} ->
            check_blacklist(VerifiedToken);
        {error, Reason} ->
            {error, {verification_failed, Reason}}
    end.

check_blacklist(#{id := TokenID, authority_id := AuthorityID} = TokenData) ->
    case tk_blacklist:is_blacklisted(TokenID, AuthorityID) of
        false ->
            {ok, TokenData};
        true ->
            {error, blacklisted}
    end.

issue(TokenType, TokenData) ->
    Handler = get_token_handler(TokenType),
    Handler:issue(TokenData).

get_token_handler(jwt) ->
    tk_token_jwt;
get_token_handler(compact) ->
    tk_token_compact.
