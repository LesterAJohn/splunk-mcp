# Splunk API Catalog (Bundled)

This report is generated from `src/data/splunk-api-catalog.json`.

Total endpoints: **427**

## Category Summary

| Category | Count |
|---|---:|
| {owner} | 6 |
| {user} | 6 |
| admin | 22 |
| alerts | 5 |
| apps | 8 |
| auth | 1 |
| authentication | 13 |
| authorization | 8 |
| catalog | 5 |
| cluster | 46 |
| collector | 11 |
| configs | 2 |
| data | 94 |
| datamodel | 5 |
| deployment | 16 |
| directory | 2 |
| health | 1 |
| indexing | 2 |
| itay | 1 |
| kvstore | 4 |
| licenser | 14 |
| mark | 1 |
| messages | 2 |
| nobody | 2 |
| properties | 4 |
| receivers | 2 |
| replication | 2 |
| root | 1 |
| saved | 11 |
| scheduled | 6 |
| search | 36 |
| server | 43 |
| shcluster | 22 |
| stack-explainer | 5 |
| storage | 5 |
| upgrade | 3 |
| workloads | 10 |

## {owner}

Count: **6**

- /servicesNS/{owner}/{app}/data/ui/views/{dashboard_id}/disable
- /servicesNS/{owner}/{app}/data/ui/views/{dashboard_id}/enable
- /servicesNS/{owner}/{app}/storage/collections/config
- /servicesNS/{owner}/{app}/storage/collections/config/{collection}
- /servicesNS/{owner}/{app}/storage/collections/data/{collection}
- /servicesNS/{owner}/{app}/storage/collections/data/{collection}/{key}

## {user}

Count: **6**

- /servicesNS/{user}/{app_name}/data/ui/panels
- /servicesNS/{user}/{app_name}/data/ui/views
- /servicesNS/{user}/{app_name}/data/ui/views/{name}
- /servicesNS/{user}/{app_name}/data/ui/views/{name}/history
- /servicesNS/{user}/{app_name}/data/ui/views/{name}/revision -d {revision_id}
- /servicesNS/{user}/{app}/

## admin

Count: **22**

- /services/admin/auth-services
- /services/admin/LDAP-groups
- /services/admin/metrics-reload/_reload
- /services/admin/ProxySSO-auth
- /services/admin/ProxySSO-auth/{proxy_name}
- /services/admin/ProxySSO-auth/{proxy_name}/disable
- /services/admin/ProxySSO-auth/{proxy_name}/enable
- /services/admin/ProxySSO-groups
- /services/admin/ProxySSO-groups/{group_name}
- /services/admin/ProxySSO-user-role-map
- /services/admin/ProxySSO-user-role-map/{user_name}
- /services/admin/replicate-SAML-certs
- /services/admin/Rsa-MFA
- /services/admin/Rsa-MFA-config-verify/
- /services/admin/SAML-groups
- /services/admin/SAML-groups/{group_name}
- /services/admin/SAML-idp-metadata
- /services/admin/SAML-sp-metadata
- /services/admin/SAML-user-role-map
- /services/admin/SAML-user-role-map/{name}
- /services/admin/summarization/
- /services/admin/summarization/tstats:DM_{app}_{data_model_ID}

## alerts

Count: **5**

- /services/alerts/alert_actions
- /services/alerts/fired_alerts
- /services/alerts/fired_alerts/{name}
- /services/alerts/metric_alerts
- /services/alerts/metric_alerts/{alert_name}

## apps

Count: **8**

- /services/apps/appinstall
- /services/apps/apptemplates
- /services/apps/apptemplates/{name}
- /services/apps/local
- /services/apps/local/{name}
- /services/apps/local/{name}/package
- /services/apps/local/{name}/setup
- /services/apps/local/{name}/update

## auth

Count: **1**

- /services/auth/login

## authentication

Count: **13**

- /services/authentication/current-context
- /services/authentication/httpauth-tokens
- /services/authentication/httpauth-tokens/{name}
- /services/authentication/providers/LDAP
- /services/authentication/providers/LDAP/{LDAP_strategy_name}
- /services/authentication/providers/LDAP/{LDAP_strategy_name}/disable
- /services/authentication/providers/LDAP/{LDAP_strategy_name}/enable
- /services/authentication/providers/SAML
- /services/authentication/providers/SAML/{stanza_name}
- /services/authentication/providers/SAML/{stanza_name}/disable
- /services/authentication/providers/SAML/{stanza_name}/enable
- /services/authentication/users
- /services/authentication/users/{name}

## authorization

Count: **8**

- /services/authorization/capabilities
- /services/authorization/fieldfilters
- /services/authorization/fieldfilters/{name}
- /services/authorization/grantable_capabilities
- /services/authorization/roles
- /services/authorization/roles/{name}
- /services/authorization/tokens
- /services/authorization/tokens/name}

## catalog

Count: **5**

- /services/catalog/metricstore/dimensions
- /services/catalog/metricstore/dimensions/{dimension-name}/values
- /services/catalog/metricstore/metrics
- /services/catalog/metricstore/rollup
- /services/catalog/metricstore/rollup/{index}

## cluster

Count: **46**

- /services/cluster/config
- /services/cluster/config/config
- /services/cluster/manager/buckets
- /services/cluster/manager/buckets/{bucket_id}/fix
- /services/cluster/manager/buckets/{bucket_id}/fix_corrupt_bucket
- /services/cluster/manager/buckets/{bucket_id}/freeze
- /services/cluster/manager/buckets/{bucket_id}/remove_all
- /services/cluster/manager/buckets/{bucket_id}/remove_from_peer
- /services/cluster/manager/buckets/{name}
- /services/cluster/manager/control/control/prune_index
- /services/cluster/manager/control/control/rebalance_primaries
- /services/cluster/manager/control/control/remove_peers
- /services/cluster/manager/control/control/resync_bucket_from_peer
- /services/cluster/manager/control/control/roll-hot-buckets
- /services/cluster/manager/control/control/rolling_upgrade_finalize
- /services/cluster/manager/control/control/rolling_upgrade_init
- /services/cluster/manager/control/default/abort_restart
- /services/cluster/manager/control/default/apply
- /services/cluster/manager/control/default/cancel_bundle_push
- /services/cluster/manager/control/default/maintenance
- /services/cluster/manager/control/default/rollback
- /services/cluster/manager/control/default/validate_bundle
- /services/cluster/manager/fixup
- /services/cluster/manager/generation
- /services/cluster/manager/generation/{name}
- /services/cluster/manager/ha_active_status
- /services/cluster/manager/health
- /services/cluster/manager/indexes
- /services/cluster/manager/indexes/{name}
- /services/cluster/manager/info
- /services/cluster/manager/peers
- /services/cluster/manager/peers/{name}
- /services/cluster/manager/redundancy
- /services/cluster/manager/sites
- /services/cluster/manager/sites/{name}
- /services/cluster/manager/status
- /services/cluster/peer/buckets
- /services/cluster/peer/buckets/{name}
- /services/cluster/peer/control/control/decommission
- /services/cluster/peer/control/control/re-add-peer
- /services/cluster/peer/control/control/set_manual_detention
- /services/cluster/peer/info
- /services/cluster/searchhead/generation
- /services/cluster/searchhead/generation/{name}
- /services/cluster/searchhead/searchheadconfig
- /services/cluster/searchhead/searchheadconfig/{name}

## collector

Count: **11**

- /services/collector
- /services/collector/ack
- /services/collector/event
- /services/collector/event/1.0
- /services/collector/health
- /services/collector/health/1.0
- /services/collector/mint
- /services/collector/mint/1.0
- /services/collector/raw
- /services/collector/raw/1.0
- /services/collector/s2s

## configs

Count: **2**

- /services/configs/conf-{file}
- /services/configs/conf-{file}/{stanza}

## data

Count: **94**

- /services/data/commands
- /services/data/commands/{name}
- /services/data/federated/index
- /services/data/federated/index/{federated_index_name}/disable
- /services/data/federated/index/{federated_index_name}/enable
- /services/data/federated/provider
- /services/data/federated/provider/{federated_index_name}
- /services/data/federated/provider/{federated_provider_name}
- /services/data/federated/provider/{federated_provider_name}/disable
- /services/data/federated/provider/{federated_provider_name}/enable
- /services/data/federated/provider/turnOffProvidersInBatch
- /services/data/federated/settings/general
- /services/data/index-volumes
- /services/data/index-volumes/{name}
- /services/data/indexes
- /services/data/indexes-extended
- /services/data/indexes-extended/{name}
- /services/data/indexes/{name}
- /services/data/ingest/rfsdestinations
- /services/data/ingest/rulesets
- /services/data/ingest/rulesets/{name}
- /services/data/ingest/rulesets/publish
- /services/data/inputs/ad
- /services/data/inputs/ad/{name}
- /services/data/inputs/all
- /services/data/inputs/all/{name}
- /services/data/inputs/http
- /services/data/inputs/http/{name}
- /services/data/inputs/http/{name}/disable
- /services/data/inputs/http/{name}/enable
- /services/data/inputs/http/{name}/rotate
- /services/data/inputs/http/connections
- /services/data/inputs/http/connections/{ip_address}
- /services/data/inputs/monitor
- /services/data/inputs/monitor/{name}
- /services/data/inputs/monitor/{name}/members
- /services/data/inputs/oneshot
- /services/data/inputs/oneshot/{name}
- /services/data/inputs/registry
- /services/data/inputs/registry/{name}
- /services/data/inputs/script
- /services/data/inputs/script/{name}
- /services/data/inputs/script/restart
- /services/data/inputs/tcp/cooked
- /services/data/inputs/tcp/cooked/{name}
- /services/data/inputs/tcp/cooked/{name}/connections
- /services/data/inputs/tcp/raw
- /services/data/inputs/tcp/raw/{name}
- /services/data/inputs/tcp/raw/{name}/connections
- /services/data/inputs/tcp/splunktcptoken
- /services/data/inputs/tcp/splunktcptoken/{name}
- /services/data/inputs/tcp/ssl
- /services/data/inputs/tcp/ssl/{name}
- /services/data/inputs/udp
- /services/data/inputs/udp/{name}
- /services/data/inputs/udp/{name}/connections
- /services/data/inputs/win-event-log-collections
- /services/data/inputs/win-event-log-collections/{name}
- /services/data/inputs/win-perfmon
- /services/data/inputs/win-perfmon/{name}
- /services/data/inputs/win-wmi-collections
- /services/data/inputs/win-wmi-collections/{name}
- /services/data/lookup-table-files/
- /services/data/lookup-table-files/{name}
- /services/data/modular-inputs
- /services/data/modular-inputs/{name}
- /services/data/outputs/tcp/default
- /services/data/outputs/tcp/default/{name}
- /services/data/outputs/tcp/group
- /services/data/outputs/tcp/group/{name}
- /services/data/outputs/tcp/server
- /services/data/outputs/tcp/server/{name}
- /services/data/outputs/tcp/server/{name}/allconnections
- /services/data/outputs/tcp/syslog
- /services/data/outputs/tcp/syslog/{name}
- /services/data/props/calcfields
- /services/data/props/calcfields/{name}
- /services/data/props/extractions
- /services/data/props/extractions/{name}
- /services/data/props/fieldaliases
- /services/data/props/fieldaliases/{name}
- /services/data/props/lookups
- /services/data/props/lookups/{name}
- /services/data/props/sourcetype-rename
- /services/data/props/sourcetype-rename/{name}
- /services/data/summaries
- /services/data/summaries/{summary_name}
- /services/data/transforms/extractions
- /services/data/transforms/extractions/{name}
- /services/data/transforms/lookups
- /services/data/transforms/lookups/{name}
- /services/data/transforms/metric-schema
- /services/data/transforms/statsdextractions
- /services/data/ui/global-banner

## datamodel

Count: **5**

- /services/datamodel/acceleration
- /services/datamodel/acceleration/{name}
- /services/datamodel/model
- /services/datamodel/model/{name}
- /services/datamodel/pivot/{name}

## deployment

Count: **16**

- /services/deployment/client
- /services/deployment/client/{name}/reload
- /services/deployment/client/config
- /services/deployment/client/config/listIsDisabled
- /services/deployment/server/applications
- /services/deployment/server/applications/{name}
- /services/deployment/server/clients
- /services/deployment/server/clients/{name}
- /services/deployment/server/clients/countClients_by_machineType
- /services/deployment/server/clients/countRecentDownloads
- /services/deployment/server/config
- /services/deployment/server/config/attributesUnsupportedInUI
- /services/deployment/server/config/listIsDisabled
- /services/deployment/server/serverclasses
- /services/deployment/server/serverclasses/{name}
- /services/deployment/server/serverclasses/rename

## directory

Count: **2**

- /services/directory
- /services/directory/{name}

## health

Count: **1**

- /services/health

## indexing

Count: **2**

- /services/indexing/preview
- /services/indexing/preview/{job_id}

## itay

Count: **1**

- /servicesNS/itay/search/storage/collections/mycollection

## kvstore

Count: **4**

- /services/kvstore/backup/create
- /services/kvstore/backup/restore
- /services/kvstore/control/maintenance
- /services/kvstore/status

## licenser

Count: **14**

- /services/licenser/groups
- /services/licenser/groups/{name}
- /services/licenser/licenses
- /services/licenser/licenses/{name}
- /services/licenser/localpeer
- /services/licenser/messages
- /services/licenser/messages/{name}
- /services/licenser/peers
- /services/licenser/peers/{name}
- /services/licenser/pools
- /services/licenser/pools/{name}
- /services/licenser/stacks
- /services/licenser/stacks/{name}
- /services/licenser/usage

## mark

Count: **1**

- /servicesNS/mark/search/storage/collections/mycollection

## messages

Count: **2**

- /services/messages
- /services/messages/{name}

## nobody

Count: **2**

- /servicesNS/nobody/search
- /servicesNS/nobody/search/storage/collections/mycollection

## properties

Count: **4**

- /services/properties
- /services/properties/{file}
- /services/properties/{file}/{stanza}
- /services/properties/{file}/{stanza}/{key}

## receivers

Count: **2**

- /services/receivers/simple
- /services/receivers/stream

## replication

Count: **2**

- /services/replication/configuration/health
- /services/replication/configuration/quarantined-assets

## root

Count: **1**

- /services/

## saved

Count: **11**

- /services/saved/bookmarks/monitoring_console
- /services/saved/eventtypes
- /services/saved/eventtypes/{name}
- /services/saved/searches
- /services/saved/searches/{name}
- /services/saved/searches/{name}/acknowledge
- /services/saved/searches/{name}/dispatch
- /services/saved/searches/{name}/history
- /services/saved/searches/{name}/reschedule
- /services/saved/searches/{name}/scheduled_times
- /services/saved/searches/{name}/suppress

## scheduled

Count: **6**

- /services/scheduled/views
- /services/scheduled/views/{name}
- /services/scheduled/views/{name}/dispatch
- /services/scheduled/views/{name}/history
- /services/scheduled/views/{name}/reschedule
- /services/scheduled/views/{name}/scheduled_times

## search

Count: **36**

- /services/search/concurrency-settings
- /services/search/concurrency-settings/scheduler
- /services/search/concurrency-settings/search
- /services/search/distributed/bundle-replication-files
- /services/search/distributed/bundle-replication-files/{name}
- /services/search/distributed/bundle/replication/config
- /services/search/distributed/bundle/replication/cycles
- /services/search/distributed/config
- /services/search/distributed/peers
- /services/search/fields
- /services/search/fields/{field_name}
- /services/search/fields/{field_name}/tags
- /services/search/jobs
- /services/search/jobs/{search_id}
- /services/search/jobs/{search_id}/control
- /services/search/jobs/{search_id}/events
- /services/search/jobs/{search_id}/results
- /services/search/jobs/{search_id}/results_preview
- /services/search/jobs/{search_id}/search.log
- /services/search/jobs/{search_id}/summary
- /services/search/jobs/{search_id}/timeline
- /services/search/jobs/export
- /services/search/parser
- /services/search/scheduler
- /services/search/scheduler/status
- /services/search/tags
- /services/search/tags/{tag_name}
- /services/search/timeparser
- /services/search/typeahead
- /services/search/v1/jobs/export
- /services/search/v2/jobs/{search_id}/events
- /services/search/v2/jobs/{search_id}/results
- /services/search/v2/jobs/{search_id}/results_preview
- /services/search/v2/jobs/export
- /services/search/v2/parser
- /services/search/workloads/policy/search_admission_control

## server

Count: **43**

- /services/server/control
- /services/server/control/restart
- /services/server/control/restart_webui
- /services/server/health-config
- /services/server/health-config/alert_action:{action_name}
- /services/server/health-config/feature:{feature_name}
- /services/server/health/deployment
- /services/server/health/deployment/details
- /services/server/health/splunkd
- /services/server/health/splunkd/details
- /services/server/httpsettings/proxysettings
- /services/server/httpsettings/proxysettings/proxyConfig
- /services/server/info
- /services/server/introspection
- /services/server/introspection/indexer
- /services/server/introspection/kvstore
- /services/server/introspection/kvstore/collectionstats
- /services/server/introspection/kvstore/replicasetstats
- /services/server/introspection/kvstore/serverstatus
- /services/server/introspection/search/dispatch
- /services/server/introspection/search/dispatch/Bundle_Directory_Reaper
- /services/server/introspection/search/dispatch/Compute_User_Search_Quota
- /services/server/introspection/search/dispatch/Dispatch_Directory_Reaper
- /services/server/introspection/search/dispatch/Search_StartUp_Time
- /services/server/introspection/search/distributed
- /services/server/introspection/search/saved
- /services/server/logger
- /services/server/logger/{name}
- /services/server/pipelinesets
- /services/server/roles
- /services/server/security/rotate-splunk-secret
- /services/server/settings
- /services/server/status
- /services/server/status/dispatch-artifacts
- /services/server/status/fishbucket
- /services/server/status/installed-file-integrity
- /services/server/status/limits/search-concurrency
- /services/server/status/partitions-space
- /services/server/status/resource-usage
- /services/server/status/resource-usage/hostwide
- /services/server/status/resource-usage/iostats
- /services/server/status/resource-usage/splunk-processes
- /services/server/sysinfo

## shcluster

Count: **22**

- /services/shcluster/captain/artifacts
- /services/shcluster/captain/artifacts/{name}
- /services/shcluster/captain/control/control/rotate-splunk-secret
- /services/shcluster/captain/control/control/upgrade-finalize
- /services/shcluster/captain/control/control/upgrade-init
- /services/shcluster/captain/control/default/restart
- /services/shcluster/captain/info
- /services/shcluster/captain/jobs
- /services/shcluster/captain/jobs/{name}
- /services/shcluster/captain/kvmigrate/start
- /services/shcluster/captain/kvmigrate/status
- /services/shcluster/captain/kvmigrate/stop
- /services/shcluster/captain/members
- /services/shcluster/captain/members/{name}
- /services/shcluster/config
- /services/shcluster/config/config
- /services/shcluster/member/artifacts
- /services/shcluster/member/artifacts/{name}
- /services/shcluster/member/consensus
- /services/shcluster/member/control/control/set_manual_detention
- /services/shcluster/member/info
- /services/shcluster/status

## stack-explainer

Count: **5**

- /services/stack-explainer/v1/node-identity
- /services/stack-explainer/v1/node-identity/{guid}
- /services/stack-explainer/v1/topology
- /services/stack-explainer/v1/trusted-connections
- /services/stack-explainer/v1/trusted-connections/{guid}

## storage

Count: **5**

- /services/storage/passwords
- /services/storage/passwords/:uname:
- /services/storage/passwords/{name}
- /servicesNS/storage/collections/data/{collection}/batch_find
- /servicesNS/storage/collections/data/{collection}/batch_save

## upgrade

Count: **3**

- /services/upgrade/shc/recovery
- /services/upgrade/shc/status
- /services/upgrade/shc/upgrade

## workloads

Count: **10**

- /services/workloads/categories
- /services/workloads/config/disable
- /services/workloads/config/enable
- /services/workloads/config/get-base-dirname
- /services/workloads/config/preflight-checks
- /services/workloads/config/set-base-dirname
- /services/workloads/pools
- /services/workloads/rules
- /services/workloads/rules/rule_name
- /services/workloads/status

