-module(tk_token_compact).

-define(HDR_SIGN, "tkc1:").
-define(PTERM_KEY(Key), {?MODULE, Key}).
-define(KEY_BY_NAME(KeyName), ?PTERM_KEY({key_name, KeyName})).
-define(KEY_BY_AUTHORITY(AuthorityID), ?PTERM_KEY({keyname_of_authority, AuthorityID})).
-define(AUTHORITY_BY_KEY_NAME(KeyName), ?PTERM_KEY({authority_of_keyname, KeyName})).

%%

-behaviour(supervisor).
-export([init/1]).

%%

-behaviour(tk_token).
-export([child_spec/1]).
-export([verify/1]).
-export([issue/1]).

%%

-type opts() :: #{
    authority_bindings := authority_bindings(),
    keyset := keyset()
}.

-type key_name() :: binary().
-type key() :: binary().

-type key_opts() :: #{
    source := keysource()
}.

-type authority_bindings() :: #{authority_id() => key_name()}.
-type keyset() :: #{key_name() => key_opts()}.

-type keysource() :: {pem_file, file:filename()}.

%%

-type authority_id() :: tk_token:authority_id().
-type token_data() :: tk_token:token_data().
-type token_string() :: tk_token:token_string().
-type token_id() :: tk_token:token_id().

%%---------------------------

-spec child_spec(opts()) -> supervisor:child_spec().
child_spec(TokenOpts) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, TokenOpts]},
        type => supervisor
    }.

%%

-spec init(opts()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Opts) ->
    ok = load_options(Opts),
    {ok, {#{}, []}}.

%% API functions

-spec verify(token_string()) ->
    {ok, token_data()} | {error, {invalid_token, Reason :: term()} | key_not_found}.
verify(Token) ->
    case do_verify(Token) of
        {ok, AuthDataID, KeyName} ->
            {ok, construct_token_data(AuthDataID, get_authority_by_key_name(KeyName))};
        {error, _} = Error ->
            Error
    end.

-spec issue(token_data()) ->
    {ok, token_string()} | {error, authority_does_not_exist}.
issue(#{type := compact, id := AuthDataID, authority_id := AuthorityID}) ->
    do_issue(get_key_by_authority(AuthorityID), AuthDataID).

%%---------------------------
%%  private functions

do_verify(<<?HDR_SIGN, KeyNameSzEncoded:8, Rest/binary>>) ->
    try
        KeyNameSz = decode_keyname_length(KeyNameSzEncoded),
        <<KeyNameEncoded:KeyNameSz/binary, TokenBody/binary>> = Rest,
        KeyName = base64:decode(KeyNameEncoded),
        case get_token_id(get_key_by_name(KeyName), TokenBody) of
            {ok, ID} -> {ok, ID, KeyName};
            {error, _} = Error -> Error
        end
    catch
        %% badarg | {badmatch, _}
        error:Reason ->
            {error, {invalid_token, Reason}}
    end;
do_verify(_) ->
    {error, {invalid_token, wrong_header}}.

construct_token_data(AuthDataID, AuthorityID) ->
    #{
        id => AuthDataID,
        type => compact,
        payload => undefined,
        authority_id => AuthorityID
    }.

%%

-spec get_token_id(key() | undefined, token_string()) -> {ok, token_id()} | {error, key_not_found}.
get_token_id(undefined, _TokenBody) ->
    {error, key_not_found};
get_token_id(Key, TokenBody) ->
    SaltedData = encrypt(Key, base64:decode(TokenBody), false),
    {AuthDataID, _Salt} = erlang:binary_to_term(SaltedData),
    {ok, AuthDataID}.

-spec do_issue({key_name(), key()} | undefined, token_id()) -> {ok, token_string()} | {error, key_not_found}.
do_issue(undefined, _AuthDataID) ->
    {error, key_not_found};
do_issue({KeyName, Key}, AuthDataID) ->
    SaltedData = erlang:term_to_binary({AuthDataID, os:timestamp()}),
    EncryptedID = encrypt(Key, SaltedData, true),
    KeyNameEncoded = base64:encode(KeyName),
    KeyNameSzEncoded = encode_keyname_length(size(KeyNameEncoded)),
    {ok, <<?HDR_SIGN, KeyNameSzEncoded:8, KeyNameEncoded/binary, (base64:encode(EncryptedID))/binary>>}.

encrypt(Key, Data, Encrypt) ->
    crypto:crypto_one_time(
        'aes_256_ecb',
        crypto:hash(sha256, Key),
        Data,
        [{encrypt, Encrypt}, {padding, pkcs_padding}]
    ).

%%

%% printable chars: ! - ~ (codes: 33 - 126, max.size = 93)
encode_keyname_length(Sz) when Sz < ($~ - $!) ->
    $! + Sz;
encode_keyname_length(_) ->
    exit(keyname_too_long).

decode_keyname_length(Sz) when Sz >= $!, Sz =< $~ ->
    Sz - $!;
decode_keyname_length(_) ->
    exit(wrong_keyname_length).

%% key management

-spec load_options(opts()) -> ok.
load_options(#{keyset := KeySet, authority_bindings := AuthorityBindings}) ->
    Fun = fun(AuthorityID, KeyName) ->
        Key =
            case maps:get(KeyName, KeySet, undefined) of
                undefined ->
                    exit({import_error, KeyName, keyset_not_found});
                #{source := Source} ->
                    store_key(KeyName, load_key(Source))
            end,
        ok = store_authority(AuthorityID, KeyName, Key)
    end,
    maps:foreach(Fun, AuthorityBindings).

load_key({pem_file, Filename} = Source) ->
    case file:read_file(Filename) of
        {ok, Binary} ->
            %% both 'SubjectPublicKeyInfo' && 'RSAPrivateKey'
            [{_, Key, not_encrypted}] = public_key:pem_decode(Binary),
            Key;
        {error, Reason} ->
            exit({import_error, Source, Reason})
    end.

get_key_by_name(KeyName) ->
    persistent_term:get(?KEY_BY_NAME(KeyName), undefined).

store_key(KeyName, Key) ->
    persistent_term:put(?KEY_BY_NAME(KeyName), Key),
    Key.

%%

store_authority(AuthorityID, KeyName, Key) ->
    ok = persistent_term:put(?KEY_BY_AUTHORITY(AuthorityID), {KeyName, Key}),
    ok = persistent_term:put(?AUTHORITY_BY_KEY_NAME(KeyName), AuthorityID),
    ok.

get_key_by_authority(AuthorityID) ->
    persistent_term:get(?KEY_BY_AUTHORITY(AuthorityID), undefined).

get_authority_by_key_name(KeyName) ->
    persistent_term:get(?AUTHORITY_BY_KEY_NAME(KeyName), undefined).
