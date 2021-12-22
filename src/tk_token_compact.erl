%%% % @noformat
-module(tk_token_compact).

-include("token_compact.hrl").

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
    {ok, token_string()} | {error, key_not_found}.
issue(#{type := compact, authority_id := AuthorityID} = TokenData) ->
    do_issue(get_key_by_authority(AuthorityID), TokenData).

%%---------------------------
%%  private functions

construct_token_data(AuthDataID, AuthorityID) ->
    #{
        id => AuthDataID,
        type => compact,
        payload => undefined,
        authority_id => AuthorityID
    }.

do_verify(<<?TOKEN_COMPACT_HDR_SIGN, Rest/binary>>) ->
    try
        {KeyName, Tail1} = decode_frame(Rest),
        {AuthDataID, Sign} = decode_frame(Tail1),
        case verify(get_key_by_name(KeyName), AuthDataID, KeyName, Sign) of
            true ->
                {ok, AuthDataID, KeyName};
            false ->
                {error, {invalid_token, sign_mismatch}};
            {error, _} = Error ->
                Error
        end
    catch
        %% badarg | {badmatch, _}
        error:Reason ->
            {error, {invalid_token, Reason}}
    end;
do_verify(_) ->
    {error, {invalid_token, wrong_header}}.

-spec do_issue({key_name(), key()} | undefined, token_data()) ->
    {ok, token_string()} | {error, key_not_found}.
do_issue(undefined, _TokenData) ->
    {error, key_not_found};
do_issue({KeyName, Key}, #{id := AuthDataID}) ->
    {ok,
        <<?TOKEN_COMPACT_HDR_SIGN,
            (encode_frame(KeyName))/binary,
            (encode_frame(AuthDataID))/binary,
            (sign(Key, AuthDataID, KeyName))/binary>>
    }.

%%

sign(Key, Data, AAD) ->
    {_, Tag} = crypto:crypto_one_time_aead(
        'aes_256_gcm',
        crypto:hash(sha256, Key),
        get_ivector(),
        Data,
        AAD,
        true
    ),
    base64:encode(Tag).

verify(undefined, _, _, _) ->
    {error, key_not_found};
verify(Key, Data, AAD, Tag) ->
    Tag =:= sign(Key, Data, AAD).

get_ivector() ->
    crypto:hash(sha256, <<"qb4wY0NzbqZND976m1NO5lAt5Or5pzj6VKLcXcaJT5Y">>).

%%

encode_frame(Bin) ->
    Encoded = base64:encode(Bin),
    <<(encode_length(size(Encoded))):8, Encoded/binary>>.

decode_frame(<<FrameSzEncoded:8, Tail/binary>>) ->
    Sz = decode_length(FrameSzEncoded),
    <<FrameData:Sz/binary, Rest/binary>> = Tail,
    {base64:decode(FrameData), Rest};
decode_frame(_) ->
    exit(wrong_format).

%% printable chars: ! - ~ (codes: 33 - 126, max.size = 93)
encode_length(Sz) when Sz < ($~ - $!) ->
    $! + Sz;
encode_length(_) ->
    exit(oversize).

decode_length(Sz) when Sz >= $!, Sz =< $~ ->
    Sz - $!;
decode_length(_) ->
    exit(wrong_length).

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
