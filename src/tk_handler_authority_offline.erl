-module(tk_handler_authority_offline).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

-export([get_handler_spec/2]).

%% Woody handler

-behaviour(tk_handler).
-export([handle_function/4]).

-type handler_config() :: #{
    token := token_opts(),
    storage := storage_opts()
}.

-type opts() :: #{
    authority_id := tk_token:authority_id(),
    token_type := tk_token:token_type(),
    storage_name := tk_storage:storage_name()
}.

-export_type([handler_config/0]).
-export_type([opts/0]).

%% Internal types

-type storage_opts() :: #{
    name := tk_storage:storage_name()
}.

-type token_opts() :: #{
    type := tk_token:token_type()
}.

-type authority_id() :: tk_authdata:authority_id().

%%

-spec get_handler_spec(authority_id(), handler_config()) -> woody:th_handler().
get_handler_spec(AuthorityID, Config) ->
    Token = maps:get(token, Config),
    Storage = maps:get(storage, Config),
    {
        {tk_token_keeper_thrift, 'TokenAuthority'},
        {?MODULE, #{
            authority_id => AuthorityID,
            token_type => maps:get(type, Token),
            storage_name => maps:get(name, Storage)
        }}
    }.

%%

-spec handle_function(woody:func(), woody:args(), opts(), tk_handler:state()) -> {ok, woody:result()} | no_return().
handle_function('Create' = Op, {ID, ContextFragment, Metadata}, Opts, State) ->
    %% Create - создает новую AuthData, используя переданные в качестве
    %% аргументов данные и сохраняет их в хранилище, после чего выписывает
    %% новый JWT-токен, в котором содержится AuthDataID (на данный момент
    %% предполагается, что AuthDataID == jwt-клейму “JTI”). По умолчанию
    %% status токена - active; authority - id выписывающей authority.
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    AuthData = create_auth_data(ID, ContextFragment, Metadata),
    case store(AuthData, Opts, get_context(State1)) of
        ok ->
            {ok, Token} = tk_token:issue(create_token_data(ID, Opts)),
            EncodedAuthData = encode_auth_data(AuthData#{token => Token}),
            _ = pulse_op_succeeded(Op, State1),
            {ok, EncodedAuthData};
        {error, exists} ->
            _ = pulse_op_failed(Op, exists, State1),
            woody_error:raise(business, #token_keeper_AuthDataAlreadyExists{})
    end;
handle_function('Get' = Op, {ID}, Opts, State) ->
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    case get_authdata(ID, Opts, get_context(State1)) of
        {ok, AuthDataPrototype} ->
            %% The initial token is not recoverable at this point
            EncodedAuthData = encode_auth_data(AuthDataPrototype),
            _ = pulse_op_succeeded(Op, State1),
            {ok, EncodedAuthData};
        {error, Reason} ->
            _ = pulse_op_failed(Op, Reason, State1),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end;
handle_function('Revoke' = Op, {ID}, Opts, State) ->
    _ = pulse_op_stated(Op, State),
    State1 = save_pulse_metadata(#{authdata_id => ID}, State),
    case revoke(ID, Opts, get_context(State1)) of
        ok ->
            _ = pulse_op_succeeded(Op, State1),
            {ok, ok};
        {error, notfound = Reason} ->
            _ = pulse_op_failed(Op, Reason, State1),
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end.

%% Internal functions

create_auth_data(ID, ContextFragment, Metadata) ->
    tk_authdata:create_prototype(ID, ContextFragment, Metadata).

create_token_data(ID, #{authority_id := AuthorityID, token_type := TokenType}) ->
    #{
        id => ID,
        type => TokenType,
        authority_id => AuthorityID,
        expiration => unlimited,
        payload => #{}
    }.

%%

get_authdata(ID, #{storage_name := StorageName}, #{woody_context := WoodyContext}) ->
    tk_storage:get(ID, StorageName, WoodyContext).

store(AuthData, #{storage_name := StorageName}, #{woody_context := WoodyContext}) ->
    tk_storage:store(AuthData, StorageName, WoodyContext).

revoke(ID, #{storage_name := StorageName}, #{woody_context := WoodyContext}) ->
    tk_storage:revoke(ID, StorageName, WoodyContext).

%%

get_context(#{context := Context}) ->
    Context.

encode_auth_data(
    #{
        id := ID,
        status := Status,
        context := Context
    } = AuthData
) ->
    #token_keeper_AuthData{
        id = ID,
        token = maps:get(token, AuthData, undefined),
        status = Status,
        context = Context,
        metadata = maps:get(metadata, AuthData, #{})
    }.

%%

save_pulse_metadata(Metadata, State = #{pulse_metadata := PulseMetadata}) ->
    State#{pulse_metadata => maps:merge(Metadata, PulseMetadata)}.

pulse_op_stated(Op, State) ->
    handle_beat(Op, started, State).

pulse_op_succeeded(Op, State) ->
    handle_beat(Op, succeeded, State).

pulse_op_failed(Op, Reason, State) ->
    handle_beat(Op, {failed, Reason}, State).

encode_beat_op('Create') ->
    {authority, {offline, create}};
encode_beat_op('Get') ->
    {authority, {offline, get}};
encode_beat_op('Revoke') ->
    {authority, {offline, revoke}}.

handle_beat(Op, Event, #{pulse_metadata := PulseMetadata, pulse := Pulse}) ->
    tk_pulse:handle_beat({encode_beat_op(Op), Event}, PulseMetadata, Pulse).
