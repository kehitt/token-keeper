-module(tk_token_jwt).
-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

%%

-behaviour(supervisor).
-export([init/1]).

%%

-behaviour(tk_token).
-export([child_spec/1]).
-export([verify/2]).
-export([issue/1]).

%%

-type opts() :: #{
    authority_bindings := authority_bindings(),
    keyset := keyset()
}.

-type key_name() :: binary().

-type key_opts() :: #{
    source := keysource()
}.

-type authority_bindings() :: #{key_name() => authority_id()}.
-type keyset() :: #{key_name() => key_opts()}.

-export_type([opts/0]).
-export_type([authority_bindings/0]).
-export_type([key_name/0]).
-export_type([key_opts/0]).
-export_type([keyset/0]).

%%

-type keysource() :: {pem_file, file:filename()}.
-type authority_id() :: tk_token:authority_id().
-type source_context() :: tk_token:source_context().
-type token_data() :: tk_token:token_data().
-type token_string() :: tk_token:token_string().

%%

-define(CLAIM_TOKEN_ID, <<"jti">>).
-define(CLAIM_EXPIRES_AT, <<"exp">>).

-define(PTERM_KEY(Key), {?MODULE, Key}).
-define(KEY_BY_KEY_ID(KeyID), ?PTERM_KEY({key_id, KeyID})).
-define(KEY_BY_KEY_NAME(KeyName), ?PTERM_KEY({key_name, KeyName})).

-define(AUTHORITY_OF_KEY_NAME(KeyName), ?PTERM_KEY({authority_of_keyname, KeyName})).
-define(KEY_NAME_OF_AUTHORITY(AuthorityID), ?PTERM_KEY({keyname_of_authority, AuthorityID})).

%%

-spec child_spec(opts()) -> supervisor:child_spec().
child_spec(TokenOpts) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, TokenOpts]},
        type => supervisor
    }.

%%

-spec init(opts()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(#{keyset := KeySet, authority_bindings := AuthorityBindings}) ->
    Keys = load_keys(KeySet),
    _ = assert_keys_unique(Keys),
    _ = store_keys(Keys),
    _ = store_authority_bindings(AuthorityBindings),
    {ok, {#{}, []}}.

%% API functions

-spec verify(token_string(), source_context()) ->
    {ok, token_data()}
    | {error,
        {alg_not_supported, Alg :: atom()}
        | {key_not_found, KID :: atom()}
        | {authority_does_not_exist, AuthorityID :: binary()}
        | {invalid_token, Reason :: term()}
        | invalid_signature}.
verify(Token, SourceContext) ->
    case do_verify(Token) of
        {ok, {Claims, KeyName}} ->
            case get_authority_of_key_name(KeyName) of
                AuthorityID when AuthorityID =/= undefined ->
                    {ok, construct_token_data(Claims, SourceContext, AuthorityID)};
                undefined ->
                    {error, {authority_does_not_exist, AuthorityID}}
            end;
        {error, _} = Error ->
            Error
    end.

-spec issue(token_data()) ->
    {ok, token_string()}
    | {error,
        issuing_not_supported
        | {key_does_not_exist, KeyName :: binary()}
        | {authority_does_not_exist, AuthorityID :: binary()}}.
issue(#{authority_id := AuthorityID} = TokenData) ->
    case get_key_name_of_authority(AuthorityID) of
        KeyName when KeyName =/= undefined ->
            case get_key_by_name(KeyName) of
                #{} = KeyInfo ->
                    case key_supports_signing(KeyInfo) of
                        true ->
                            {ok, issue_with_key(KeyInfo, TokenData)};
                        false ->
                            {error, issuing_not_supported}
                    end;
                undefined ->
                    {error, {key_does_not_exist, KeyName}}
            end;
        undefined ->
            {error, {authority_does_not_exist, AuthorityID}}
    end.

%% Internal functions

load_keys(KeySet) ->
    maps:fold(fun load_key/3, [], KeySet).

load_key(KeyName, KeyOpts, Acc) ->
    Source = maps:get(source, KeyOpts),
    case load_key_from_source(Source) of
        {ok, KeyID, JWK} ->
            [construct_key(KeyID, JWK, KeyName) | Acc];
        {error, Reason} ->
            exit({import_error, Source, Reason})
    end.

derive_kid_from_public_key_pem_entry(JWK) ->
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    jose_base64url:encode(crypto:hash(sha256, Data)).

load_key_from_source({pem_file, Filename}) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            KID = derive_kid_from_public_key_pem_entry(JWK),
            {ok, KID, JWK};
        Error = {error, _} ->
            Error
    end.

construct_key(KeyID, JWK, KeyName) ->
    #{
        jwk => JWK,
        key_id => KeyID,
        key_name => KeyName,
        verifier => get_verifier(JWK),
        signer => get_signer(JWK)
    }.

get_signer(JWK) ->
    try
        jose_jwk:signer(JWK)
    catch
        error:_ ->
            undefined
    end.

get_verifier(JWK) ->
    try
        jose_jwk:verifier(JWK)
    catch
        error:_ ->
            undefined
    end.

%%

assert_keys_unique(KeyInfos) ->
    lists:foldr(fun assert_key_unique/2, [], KeyInfos).

assert_key_unique(#{key_id := KeyID, key_name := KeyName}, SeenKeyIDs) ->
    case lists:member(KeyID, SeenKeyIDs) of
        true -> exit({import_error, {duplicate_kid, KeyName}});
        false -> [KeyID | SeenKeyIDs]
    end.

%%

store_keys(KeyInfos) ->
    lists:foreach(fun store_key/1, KeyInfos).

store_key(#{key_id := KeyID, key_name := KeyName} = KeyInfo) ->
    put_key(KeyID, KeyName, KeyInfo).

%% Verifying

do_verify(Token) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KeyID = get_key_id(Header),
        case get_key_by_id(KeyID) of
            #{} = KeyInfo ->
                case key_supports_verification(Alg, KeyInfo) of
                    true ->
                        verify_with_key(ExpandedToken, KeyInfo);
                    false ->
                        {error, {alg_not_supported, Alg}}
                end;
            undefined ->
                {error, {key_not_found, KeyID}}
        end
    catch
        throw:({invalid_token, {missing, _}} = Reason) ->
            {error, Reason};
        error:{badarg, Reason} ->
            {error, {invalid_token, Reason}}
    end.

base64url_to_map(Base64) when is_binary(Base64) ->
    {ok, Json} = jose_base64url:decode(Base64),
    jsx:decode(Json, [return_maps]).

get_key_id(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_key_id(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

key_supports_verification(Alg, #{verifier := Algs}) ->
    lists:member(Alg, Algs).

verify_with_key(ExpandedToken, #{jwk := JWK, key_name := KeyName}) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            _ = validate_claims(Claims),
            {ok, {Claims, KeyName}};
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

%%

construct_token_data(Claims, SourceContext, AuthorityID) ->
    #{
        id => maps:get(?CLAIM_TOKEN_ID, Claims),
        type => jwt,
        expiration => decode_expiration(maps:get(?CLAIM_EXPIRES_AT, Claims)),
        payload => Claims,
        authority_id => AuthorityID,
        source_context => SourceContext
    }.

decode_expiration(0) ->
    unlimited;
decode_expiration(Expiration) when is_integer(Expiration) ->
    Expiration.

%% Signing

key_supports_signing(#{signer := #{}}) ->
    true;
key_supports_signing(#{signer := undefined}) ->
    false.

issue_with_key(#{key_id := KeyID, jwk := JWK, signer := #{} = JWS}, TokenData) ->
    Claims = construct_claims(TokenData),
    JWT = jose_jwt:sign(JWK, JWS#{<<"kid">> => KeyID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

construct_claims(#{id := TokenID, expiration := Expiration, payload := Claims}) ->
    maps:map(fun encode_claim/2, Claims#{
        ?CLAIM_TOKEN_ID => TokenID,
        ?CLAIM_EXPIRES_AT => Expiration
    }).

encode_claim(?CLAIM_EXPIRES_AT, Expiration) ->
    encode_expires_at(Expiration);
encode_claim(_, Value) ->
    Value.

encode_expires_at(unlimited) ->
    0;
encode_expires_at(Dl) ->
    Dl.

%%

put_key(KeyID, KeyName, KeyInfo) ->
    %% Official [Erlang Reference Manual](https://www.erlang.org/doc/man/persistent_term.html) recommends
    %% storing one big persistent_term over muliple small ones, reasoning being that "the execution time for storing
    %% a persistent term is proportional to the number of already existing terms". Since we literally never add new
    %% keys after initial configuration at application start, it seems fine to do this here.
    ok = persistent_term:put(?KEY_BY_KEY_ID(KeyID), KeyInfo),
    ok = persistent_term:put(?KEY_BY_KEY_NAME(KeyName), KeyInfo),
    ok.

get_key_by_id(KeyID) ->
    persistent_term:get(?KEY_BY_KEY_ID(KeyID), undefined).

get_key_by_name(KeyName) ->
    persistent_term:get(?KEY_BY_KEY_NAME(KeyName), undefined).

%%

store_authority_bindings(AuthorityBindings) ->
    maps:foreach(fun put_authority_binding/2, AuthorityBindings).

put_authority_binding(KeyName, AuthorityID) ->
    ok = persistent_term:put(?AUTHORITY_OF_KEY_NAME(KeyName), AuthorityID),
    ok = persistent_term:put(?KEY_NAME_OF_AUTHORITY(AuthorityID), KeyName),
    ok.

get_authority_of_key_name(KeyName) ->
    persistent_term:get(?AUTHORITY_OF_KEY_NAME(KeyName), undefined).

get_key_name_of_authority(AuthorityID) ->
    persistent_term:get(?KEY_NAME_OF_AUTHORITY(AuthorityID), undefined).

%%

validate_claims(Claims) ->
    validate_claims(Claims, get_validators()).

validate_claims(Claims, [{Name, Claim, Validator} | Rest]) ->
    _ = Validator(Name, maps:get(Claim, Claims, undefined)),
    validate_claims(Claims, Rest);
validate_claims(Claims, []) ->
    Claims.

get_validators() ->
    [
        {token_id, ?CLAIM_TOKEN_ID, fun check_presence/2}
    ].

check_presence(_, V) when is_binary(V) ->
    V;
check_presence(_, V) when is_integer(V) ->
    V;
check_presence(C, undefined) ->
    throw({invalid_token, {missing, C}}).
