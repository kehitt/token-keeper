-module(token_keeper_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").

-include("token_compact.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([authenticate_invalid_token_type_fail/1]).
-export([authenticate_invalid_token_key_fail/1]).
-export([authenticate_phony_api_key_token_ok/1]).
-export([authenticate_user_session_token_ok/1]).
-export([authenticate_invoice_template_access_token_ok/1]).
-export([authenticate_invoice_template_access_token_no_access/1]).
-export([authenticate_invoice_template_access_token_invalid_access/1]).
-export([authenticate_claim_token_no_context_fail/1]).
-export([authenticate_legacy_claim_token_ok/1]).
-export([authenticate_blacklisted_jti_fail/1]).
-export([authenticate_non_blacklisted_jti_ok/1]).
-export([authenticate_ephemeral_claim_token_ok/1]).
-export([issue_ephemeral_token_ok/1]).
-export([authenticate_offline_token_not_found_fail/1]).
-export([authenticate_offline_token_revoked_fail/1]).
-export([authenticate_offline_token_ok/1]).
-export([issue_offline_token_ok/1]).
-export([issue_duplicate_offline_token_fail/1]).
-export([get_authdata_by_id_ok/1]).
-export([get_authdata_by_id_not_found_fail/1]).
-export([revoke_authdata_by_id_ok/1]).
-export([revoke_authdata_by_id_not_found_fail/1]).
-export([issue_compact_token_ok/1]).
-export([authenticate_compact_token_ok/1]).
-export([authenticate_compact_token_invalid_token_fail/1]).

-type config() :: ct_helper:config().
-type group_name() :: atom().
-type test_case_name() :: atom().

-define(CONFIG(Key, C), (element(2, lists:keyfind(Key, 1, C)))).

%%

-define(TOKEN_SOURCE_CONTEXT, ?TOKEN_SOURCE_CONTEXT(<<"http://spanish.inquisition">>)).
-define(TOKEN_SOURCE_CONTEXT(SourceURL), #token_keeper_TokenSourceContext{request_origin = SourceURL}).
-define(USER_TOKEN_SOURCE, <<"https://dashboard.rbk.money">>).

-define(META_PARTY_ID, <<"test.rbkmoney.party.id">>).
-define(META_USER_ID, <<"test.rbkmoney.user.id">>).
-define(META_USER_EMAIL, <<"test.rbkmoney.user.email">>).
-define(META_USER_REALM, <<"test.rbkmoney.user.realm">>).
-define(META_CAPI_CONSUMER, <<"test.rbkmoney.capi.consumer">>).

-define(TK_AUTHORITY_KEYCLOAK, <<"test.rbkmoney.keycloak">>).
-define(TK_AUTHORITY_APIKEYMGMT, <<"test.rbkmoney.apikeymgmt">>).
-define(TK_AUTHORITY_APIKEYTELEGRAM, <<"test.rbkmoney.apikeytelegram">>).
-define(TK_AUTHORITY_CAPI, <<"test.rbkmoney.capi">>).

-define(TK_RESOURCE_DOMAIN, <<"test-domain">>).

%%

-spec all() -> [atom()].

all() ->
    [
        {group, external_detect_token},
        {group, external_invoice_template_access_token},
        {group, external_legacy_claim},
        {group, blacklist},
        {group, ephemeral},
        {group, offline},
        {group, compact}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {external_detect_token, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_phony_api_key_token_ok,
            authenticate_user_session_token_ok
        ]},
        {external_invoice_template_access_token, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_invoice_template_access_token_ok,
            authenticate_invoice_template_access_token_no_access,
            authenticate_invoice_template_access_token_invalid_access
        ]},
        {external_legacy_claim, [parallel], [
            authenticate_claim_token_no_context_fail,
            authenticate_legacy_claim_token_ok
        ]},
        {ephemeral, [parallel], [
            authenticate_claim_token_no_context_fail,
            authenticate_ephemeral_claim_token_ok,
            issue_ephemeral_token_ok
        ]},
        {offline, [parallel], [
            authenticate_offline_token_not_found_fail,
            authenticate_offline_token_revoked_fail,
            authenticate_offline_token_ok,
            issue_offline_token_ok,
            issue_duplicate_offline_token_fail,
            get_authdata_by_id_ok,
            get_authdata_by_id_not_found_fail,
            revoke_authdata_by_id_ok,
            revoke_authdata_by_id_not_found_fail
        ]},
        {compact, [parallel], [
            issue_compact_token_ok,
            authenticate_compact_token_ok,
            authenticate_compact_token_invalid_token_fail
        ]},
        {blacklist, [parallel], [
            authenticate_blacklisted_jti_fail,
            authenticate_non_blacklisted_jti_ok
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    Apps =
        genlib_app:start_application(woody) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]),
    [{suite_apps, Apps} | C].

-spec end_per_suite(config()) -> ok.
end_per_suite(C) ->
    genlib_app:stop_unload_applications(?CONFIG(suite_apps, C)).

%% @TODO Pending configurator
-spec init_per_group(group_name(), config()) -> config().
init_per_group(external_detect_token = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_KEYCLOAK =>
                    #{
                        sources => [extract_method_detect_token()]
                    }
            }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_KEYCLOAK => ?TK_AUTHORITY_KEYCLOAK
                },
                keyset => #{
                    ?TK_AUTHORITY_KEYCLOAK => #{
                        source => {pem_file, get_filename("keys/local/public.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(external_invoice_template_access_token = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_CAPI =>
                    #{
                        sources => [extract_method_invoice_tpl_token()]
                    }
            }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_CAPI => ?TK_AUTHORITY_CAPI
                },
                keyset => #{
                    ?TK_AUTHORITY_CAPI => #{
                        source => {pem_file, get_filename("keys/local/public.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(external_legacy_claim = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_CAPI =>
                    #{
                        sources => [
                            {legacy_claim, #{
                                metadata_mappings => #{
                                    party_id => ?META_PARTY_ID,
                                    consumer => ?META_CAPI_CONSUMER
                                }
                            }}
                        ]
                    }
            }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_CAPI => ?TK_AUTHORITY_CAPI
                },
                keyset => #{
                    ?TK_AUTHORITY_CAPI => #{
                        source => {pem_file, get_filename("keys/local/public.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(blacklist = Name, C) ->
    C0 = start_keeper(
        [
            {authenticator, #{
                service => #{
                    path => <<"/v2/authenticator">>
                },
                authorities => #{
                    <<"blacklisting_authority">> =>
                        #{
                            sources => [extract_method_detect_token()]
                        },
                    ?TK_AUTHORITY_CAPI =>
                        #{
                            sources => [extract_method_detect_token()]
                        }
                }
            }},
            {tokens, #{
                jwt => #{
                    authority_bindings => #{
                        <<"blacklisting_authority">> => <<"blacklisting_authority">>,
                        ?TK_AUTHORITY_CAPI => ?TK_AUTHORITY_CAPI
                    },
                    keyset => #{
                        <<"blacklisting_authority">> => #{
                            source => {pem_file, get_filename("keys/local/private.pem", C)}
                        },
                        ?TK_AUTHORITY_CAPI => #{
                            source => {pem_file, get_filename("keys/secondary/private.pem", C)}
                        }
                    }
                }
            }}
        ],
        get_filename("blacklisted_keys.yaml", C)
    ),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(ephemeral = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_CAPI => #{
                    sources => [
                        {claim, #{}}
                    ]
                }
            }
        }},
        {authorities, #{
            ?TK_AUTHORITY_CAPI =>
                #{
                    service => #{
                        path => <<"/v2/authority/com.rbkmoney.access.capi">>
                    },
                    type =>
                        {ephemeral, #{
                            token => #{
                                type => jwt
                            }
                        }}
                }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_CAPI => ?TK_AUTHORITY_CAPI
                },
                keyset => #{
                    ?TK_AUTHORITY_CAPI => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>),
        {token_ephemeral_authority, ?TK_AUTHORITY_CAPI} => mk_url(<<"/v2/authority/com.rbkmoney.access.capi">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(offline = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_APIKEYMGMT =>
                    #{
                        sources => [
                            {storage, #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }}
                        ]
                    }
            }
        }},
        {authorities, #{
            ?TK_AUTHORITY_APIKEYMGMT =>
                #{
                    service => #{
                        path => <<"/v2/authority/com.rbkmoney.apikemgmt">>
                    },
                    type =>
                        {offline, #{
                            token => #{
                                type => jwt
                            },
                            storage => #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }
                        }}
                }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_APIKEYMGMT => ?TK_AUTHORITY_APIKEYMGMT
                },
                keyset => #{
                    ?TK_AUTHORITY_APIKEYMGMT => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    }
                }
            }
        }},
        {storages, #{
            ?TK_AUTHORITY_APIKEYMGMT =>
                {machinegun, #{
                    namespace => apikeymgmt,
                    automaton => #{
                        url => <<"http://machinegun:8022/v1/automaton">>,
                        event_handler => [scoper_woody_event_handler],
                        transport_opts => #{}
                    }
                }}
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>),
        {token_authority, ?TK_AUTHORITY_APIKEYMGMT} => mk_url(<<"/v2/authority/com.rbkmoney.apikemgmt">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(compact = Name, C) ->
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => <<"/v2/authenticator">>
            },
            authorities => #{
                ?TK_AUTHORITY_APIKEYTELEGRAM =>
                    #{
                        sources => [
                            {storage, #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }}
                        ]
                    }
            }
        }},
        {authorities, #{
            ?TK_AUTHORITY_APIKEYTELEGRAM =>
                #{
                    service => #{
                        path => <<"/v2/authority/com.rbkmoney.apikeytelegram">>
                    },
                    type =>
                        {offline, #{
                            token => #{
                                type => compact
                            },
                            storage => #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }
                        }}
                }
        }},
        {tokens, #{
            compact => #{
                authority_bindings => #{
                    ?TK_AUTHORITY_APIKEYTELEGRAM => ?TK_AUTHORITY_APIKEYMGMT
                },
                keyset => #{
                    ?TK_AUTHORITY_APIKEYMGMT => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    }
                }
            }
        }},
        {storages, #{
            ?TK_AUTHORITY_APIKEYMGMT =>
                {machinegun, #{
                    namespace => apikeymgmt,
                    automaton => #{
                        url => <<"http://machinegun:8022/v1/automaton">>,
                        event_handler => [scoper_woody_event_handler],
                        transport_opts => #{}
                    }
                }}
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(<<"/v2/authenticator">>),
        {token_authority, ?TK_AUTHORITY_APIKEYTELEGRAM} => mk_url(<<"/v2/authority/com.rbkmoney.apikeytelegram">>)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_GroupName, C) ->
    ok = stop_keeper(C),
    ok.

-spec init_per_testcase(atom(), config()) -> config().
init_per_testcase(Name, C) ->
    [{testcase, Name} | C].

-spec end_per_testcase(atom(), config()) -> config().
end_per_testcase(_Name, _C) ->
    ok.

%%

-spec authenticate_invalid_token_type_fail(config()) -> _.
authenticate_invalid_token_type_fail(C) ->
    Token = <<"BLAH">>,
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_invalid_token_key_fail(config()) -> _.
authenticate_invalid_token_key_fail(C) ->
    Token = issue_dummy_token(C),
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_phony_api_key_token_ok(config()) -> _.
authenticate_phony_api_key_token_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID},
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({api_key_token, JTI, SubjectID}, Context).

-spec authenticate_user_session_token_ok(config()) -> _.
authenticate_user_session_token_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    Claims = get_user_session_token_claims(JTI, SubjectID, SubjectEmail),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{
            ?META_USER_ID := SubjectID,
            ?META_USER_EMAIL := SubjectEmail,
            ?META_USER_REALM := <<"external">>
        },
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C),
    _ = assert_context({user_session_token, JTI, SubjectID, SubjectEmail, unlimited}, Context).

-spec authenticate_invoice_template_access_token_ok(config()) -> _.
authenticate_invoice_template_access_token_ok(C) ->
    JTI = unique_id(),
    InvoiceTemplateID = unique_id(),
    SubjectID = unique_id(),
    Claims = get_invoice_access_template_token_claims(JTI, SubjectID, InvoiceTemplateID),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID},
        authority = ?TK_AUTHORITY_CAPI
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Context).

-spec authenticate_invoice_template_access_token_no_access(config()) -> _.
authenticate_invoice_template_access_token_no_access(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_resource_access_claims(JTI, SubjectID, #{}),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_invoice_template_access_token_invalid_access(config()) -> _.
authenticate_invoice_template_access_token_invalid_access(C) ->
    JTI = unique_id(),
    InvoiceID = unique_id(),
    SubjectID = unique_id(),
    Claims = get_resource_access_claims(JTI, SubjectID, #{
        ?TK_RESOURCE_DOMAIN => #{
            <<"roles">> => [
                <<"invoices.", InvoiceID/binary, ":read">>
            ]
        }
    }),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_blacklisted_jti_fail(config()) -> _.
authenticate_blacklisted_jti_fail(C) ->
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/local/private.pem", C)),
    ?assertThrow(#token_keeper_AuthDataRevoked{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_non_blacklisted_jti_ok(config()) -> _.
authenticate_non_blacklisted_jti_ok(C) ->
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/secondary/private.pem", C)),
    ?assertMatch(#token_keeper_AuthData{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_claim_token_no_context_fail(config()) -> _.
authenticate_claim_token_no_context_fail(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_base_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_legacy_claim_token_ok(config()) -> _.
authenticate_legacy_claim_token_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Consumer = <<"client">>,
    Claims = get_claim_token_claims(JTI, SubjectID, ContextFragment, undefined, Consumer),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID, ?META_CAPI_CONSUMER := Consumer},
        authority = ?TK_AUTHORITY_CAPI
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({claim_token, JTI}, Context).

-spec authenticate_ephemeral_claim_token_ok(config()) -> _.
authenticate_ephemeral_claim_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_CAPI,
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create_ephemeral(AuthorityID, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = AuthorityID
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({claim_token, JTI}, Context).

-spec issue_ephemeral_token_ok(config()) -> _.
issue_ephemeral_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_CAPI,
    #token_keeper_AuthData{
        id = undefined,
        status = active,
        metadata = Metadata
    } = call_create_ephemeral(AuthorityID, ContextFragment, Metadata, C).

-spec authenticate_offline_token_not_found_fail(config()) -> _.
authenticate_offline_token_not_found_fail(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_base_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_offline_token_revoked_fail(config()) -> _.
authenticate_offline_token_revoked_fail(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ok = call_revoke(AuthorityID, JTI, C),
    ?assertThrow(#token_keeper_AuthDataRevoked{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_offline_token_ok(config()) -> _.
authenticate_offline_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = AuthorityID
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({claim_token, JTI}, Context).

-spec issue_offline_token_ok(config()) -> _.
issue_offline_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C).

-spec issue_duplicate_offline_token_fail(config()) -> _.
issue_duplicate_offline_token_fail(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ?assertThrow(
        #token_keeper_AuthDataAlreadyExists{},
        call_create(AuthorityID, JTI, ContextFragment, Metadata, C)
    ).

-spec get_authdata_by_id_ok(config()) -> _.
get_authdata_by_id_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = _,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = undefined,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_get(AuthorityID, JTI, C).

-spec get_authdata_by_id_not_found_fail(config()) -> _.
get_authdata_by_id_not_found_fail(C) ->
    JTI = unique_id(),
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_get(AuthorityID, JTI, C)).

-spec revoke_authdata_by_id_ok(config()) -> _.
revoke_authdata_by_id_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ok = call_revoke(AuthorityID, JTI, C),
    #token_keeper_AuthData{
        id = JTI,
        status = revoked
    } = RevokedAuthData = call_get(AuthorityID, JTI, C),
    ok = call_revoke(AuthorityID, JTI, C),
    ?assertEqual(RevokedAuthData, call_get(AuthorityID, JTI, C)).

-spec revoke_authdata_by_id_not_found_fail(config()) -> _.
revoke_authdata_by_id_not_found_fail(C) ->
    JTI = unique_id(),
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_revoke(AuthorityID, JTI, C)).

%%

-spec issue_compact_token_ok(config()) -> _.
issue_compact_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYTELEGRAM,
    #token_keeper_AuthData{
        id = JTI,
        token = _Token,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = undefined,
        status = active,
        context = _Context,
        metadata = Metadata
    } = call_get(AuthorityID, JTI, C).

-spec authenticate_compact_token_ok(config()) -> _.
authenticate_compact_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYTELEGRAM,
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = AuthorityID
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C).

-spec authenticate_compact_token_invalid_token_fail(config()) -> _.
authenticate_compact_token_invalid_token_fail(C) ->
    %% header ok, but random bytes body
    Token = <<?TOKEN_COMPACT_HDR_SIGN, (base64:encode(crypto:strong_rand_bytes(64)))/binary>>,
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

%%

get_base_claims(JTI, SubjectID) ->
    #{
        <<"jti">> => JTI,
        <<"sub">> => SubjectID,
        <<"exp">> => 0
    }.

get_phony_api_key_claims(JTI, SubjectID) ->
    get_base_claims(JTI, SubjectID).

get_user_session_token_claims(JTI, SubjectID, SubjectEmail) ->
    maps:merge(#{<<"email">> => SubjectEmail}, get_base_claims(JTI, SubjectID)).

get_resource_access_claims(JTI, SubjectID, ResourceAccess) ->
    maps:merge(#{<<"resource_access">> => ResourceAccess}, get_base_claims(JTI, SubjectID)).

get_invoice_access_template_token_claims(JTI, SubjectID, InvoiceTemplateID) ->
    get_resource_access_claims(
        JTI,
        SubjectID,
        #{
            ?TK_RESOURCE_DOMAIN => #{
                <<"roles">> => [
                    <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ".invoice_template_invoices:write">>,
                    <<"party.*.invoice_templates.", InvoiceTemplateID/binary, ":read">>
                ]
            }
        }
    ).

create_bouncer_context(JTI) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"ClaimToken">>,
            token => #{id => JTI}
        },
        bouncer_context_helpers:empty()
    ).

create_encoded_bouncer_context(JTI) ->
    Fragment = create_bouncer_context(JTI),
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_fragment_content(Fragment)
    }.

get_claim_token_claims(JTI, SubjectID, #bctx_ContextFragment{content = FragmentContent}, Metadata, Consumer) ->
    genlib_map:compact(#{
        <<"jti">> => JTI,
        <<"sub">> => SubjectID,
        <<"bouncer_ctx">> => #{
            <<"ty">> => <<"v1_thrift_binary">>,
            <<"ct">> => base64:encode(FragmentContent)
        },
        <<"tk_metadata">> => Metadata,
        <<"cons">> => Consumer,
        <<"exp">> => 0
    }).

%%

mk_client(C) ->
    WoodyCtx = woody_context:new(genlib:to_binary(?CONFIG(testcase, C))),
    ServiceURLs = ?CONFIG(service_urls, C),
    {WoodyCtx, ServiceURLs}.

call_authenticate(Token, TokenSourceContext, C) ->
    call_token_authenticator('Authenticate', {Token, TokenSourceContext}, C).

call_create_ephemeral(AuthorityID, Context, Metadata, C) ->
    call_token_ephemeral_authority(AuthorityID, 'Create', {Context, Metadata}, C).

call_create(AuthorityID, ID, Context, Metadata, C) ->
    call_token_authority(AuthorityID, 'Create', {ID, Context, Metadata}, C).

call_get(AuthorityID, ID, C) ->
    call_token_authority(AuthorityID, 'Get', {ID}, C).

call_revoke(AuthorityID, ID, C) ->
    call_token_authority(AuthorityID, 'Revoke', {ID}, C).

call_token_authenticator(Operation, Args, C) ->
    call(token_authenticator, Operation, Args, mk_client(C)).

call_token_authority(ID, Operation, Args, C) ->
    call({token_authority, ID}, Operation, Args, mk_client(C)).

call_token_ephemeral_authority(ID, Operation, Args, C) ->
    call({token_ephemeral_authority, ID}, Operation, Args, mk_client(C)).

call(ServiceName, Fn, Args, {WoodyCtx, ServiceURLs}) ->
    Service = get_service_spec(ServiceName),
    Opts = #{
        url => maps:get(ServiceName, ServiceURLs),
        event_handler => scoper_woody_event_handler
    },
    case woody_client:call({Service, Fn, Args}, Opts, WoodyCtx) of
        {ok, Response} ->
            Response;
        {exception, Exception} ->
            throw(Exception)
    end.

get_service_spec(token_authenticator) ->
    {tk_token_keeper_thrift, 'TokenAuthenticator'};
get_service_spec({token_authority, _}) ->
    {tk_token_keeper_thrift, 'TokenAuthority'};
get_service_spec({token_ephemeral_authority, _}) ->
    {tk_token_keeper_thrift, 'EphemeralTokenAuthority'}.

%%

-define(CTX_ENTITY(ID), #bouncer_base_Entity{id = ID}).

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

decode_bouncer_fragment(#bctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    {ok, Fragment, _} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

assert_context(TokenInfo, EncodedContextFragment) ->
    #bctx_v1_ContextFragment{auth = Auth, user = User} = decode_bouncer_fragment(EncodedContextFragment),
    _ = assert_auth(TokenInfo, Auth),
    _ = assert_user(TokenInfo, User).

assert_auth({claim_token, JTI}, Auth) ->
    ?assertEqual(<<"ClaimToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token);
assert_auth({api_key_token, JTI, SubjectID}, Auth) ->
    ?assertEqual(<<"ApiKeyToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch([#bctx_v1_AuthScope{party = ?CTX_ENTITY(SubjectID)}], Auth#bctx_v1_Auth.scope);
assert_auth({invoice_template_access_token, JTI, SubjectID, InvoiceTemplateID}, Auth) ->
    ?assertEqual(<<"InvoiceTemplateAccessToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertMatch(
        [
            #bctx_v1_AuthScope{
                party = ?CTX_ENTITY(SubjectID),
                invoice_template = ?CTX_ENTITY(InvoiceTemplateID)
            }
        ],
        Auth#bctx_v1_Auth.scope
    );
assert_auth({user_session_token, JTI, _SubjectID, _SubjectEmail, Exp}, Auth) ->
    ?assertEqual(<<"SessionToken">>, Auth#bctx_v1_Auth.method),
    ?assertMatch(#bctx_v1_Token{id = JTI}, Auth#bctx_v1_Auth.token),
    ?assertEqual(make_auth_expiration(Exp), Auth#bctx_v1_Auth.expiration).

assert_user({claim_token, _}, undefined) ->
    ok;
assert_user({api_key_token, _, _}, undefined) ->
    ok;
assert_user({invoice_template_access_token, _, _, _}, undefined) ->
    ok;
assert_user({user_session_token, _JTI, SubjectID, SubjectEmail, _Exp}, User) ->
    ?assertEqual(SubjectID, User#bctx_v1_User.id),
    ?assertEqual(SubjectEmail, User#bctx_v1_User.email),
    ?assertEqual(?CTX_ENTITY(<<"external">>), User#bctx_v1_User.realm).

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

%%

-include_lib("jose/include/jose_jwk.hrl").

issue_token(Claims, Config) ->
    issue_token_with(Claims, get_filename("keys/local/private.pem", Config)).

issue_token_with(Claims, PemFile) ->
    JWK = jose_jwk:from_pem_file(PemFile),
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(JWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

issue_dummy_token(Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0
    },
    BadPemFile = get_filename("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_filename("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

%%

get_filename(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

start_keeper(Authorities) ->
    start_keeper(Authorities, undefined).

start_keeper(Env, BlacklistPath) ->
    Port = 8022,
    Apps = genlib_app:start_application_with(
        token_keeper,
        [
            {port, Port},
            {blacklist, #{
                path => BlacklistPath
            }},
            {machinegun, #{
                processor => #{
                    path => <<"/v2/stateproc">>
                }
            }}
        ] ++ Env
    ),
    [{keeper_apps, Apps}].

stop_keeper(C) ->
    genlib_app:stop_unload_applications(?CONFIG(keeper_apps, C)).

mk_url(Path) ->
    mk_url("127.0.0.1", 8022, Path).

mk_url(IP, Port, Path) ->
    iolist_to_binary(["http://", IP, ":", genlib:to_binary(Port), Path]).

extract_method_detect_token() ->
    {extract_context, #{
        methods => [
            {detect_token, #{
                phony_api_key_opts => #{
                    metadata_mappings => #{
                        party_id => ?META_PARTY_ID
                    }
                },
                user_session_token_opts => #{
                    user_realm => <<"external">>,
                    metadata_mappings => #{
                        user_id => ?META_USER_ID,
                        user_email => ?META_USER_EMAIL,
                        user_realm => ?META_USER_REALM
                    }
                },
                user_session_token_origins => [?USER_TOKEN_SOURCE]
            }}
        ]
    }}.

extract_method_invoice_tpl_token() ->
    {extract_context, #{
        methods => [
            {invoice_template_access_token, #{
                domain => ?TK_RESOURCE_DOMAIN,
                metadata_mappings => #{
                    party_id => ?META_PARTY_ID
                }
            }}
        ]
    }}.
