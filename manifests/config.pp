# Author::    Liam Bennett (mailto:lbennett@opentable.com)
# Copyright:: Copyright (c) 2013 OpenTable Inc
# License::   MIT

# == Class rundeck::config
#
# This private class is called from `rundeck` to manage the configuration
#
class rundeck::config(
  $auth_types            = $rundeck::auth_types,
  $auth_template         = $rundeck::auth_template,
  $user                  = $rundeck::user,
  $group                 = $rundeck::group,
  $ssl_enabled           = $rundeck::ssl_enabled,
  $projects_organization = $rundeck::projects_default_org,
  $projects_description  = $rundeck::projects_default_desc,
  $projects              = $rundeck::projects,
  $rd_loglevel           = $rundeck::rd_loglevel,
  $rss_enabled           = $rundeck::rss_enabled,
  $clustermode_enabled   = $rundeck::clustermode_enabled,
  $grails_server_url     = $rundeck::grails_server_url,
  $database_config       = $rundeck::database_config,
  $keystore              = $rundeck::keystore,
  $keystore_password     = $rundeck::keystore_password,
  $key_password          = $rundeck::key_password,
  $truststore            = $rundeck::truststore,
  $truststore_password   = $rundeck::truststore_password,
  $service_logs_dir      = $rundeck::service_logs_dir,
  $service_name          = $rundeck::service_name,
  $mail_config           = $rundeck::mail_config,
  $jvm_args              = $rundeck::jvm_args,
  $security_config       = $rundeck::security_config,
  $acl_policies          = $rundeck::acl_policies,
) inherits rundeck::params {

  $framework_config = deep_merge($rundeck::params::framework_config, $rundeck::framework_config)
  $auth_config      = deep_merge($rundeck::params::auth_config, $rundeck::auth_config)
  $truststore_keys  = deep_merge($rundeck::params::truststore_keys, $rundeck::truststore_keys)
  $api_tokens       = deep_merge($rundeck::params::api_tokens, $rundeck::api_tokens)

  $logs_dir       = $framework_config['framework.logs.dir']
  $rdeck_base     = $framework_config['rdeck.base']
  $projects_dir   = $framework_config['framework.projects.dir']
  $properties_dir = $framework_config['framework.etc.dir']

  ensure_resource('file', $properties_dir, {'ensure' => 'directory', 'owner' => $user, 'group' => $group} )

  if 'file' in $auth_types {

    file { "${properties_dir}/realm.properties":
      owner   => $user,
      group   => $group,
      mode    => '0640',
      content => template('rundeck/realm.properties.erb'),
      require => File[$properties_dir],
      notify  => Service[$service_name],
    }

    $active_directory_auth_flag = 'sufficient'
    $ldap_auth_flag = 'sufficient'
  }
  elsif 'active_directory' in $auth_types {
    $active_directory_auth_flag = 'required'
    $ldap_auth_flag = 'sufficient'
  }
  else {
    $ldap_auth_flag = 'required'
  }

  file { "${properties_dir}/jaas-auth.conf":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template($auth_template),
    require => File[$properties_dir]
  }

  file { "${properties_dir}/log4j.properties":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template('rundeck/log4j.properties.erb'),
    notify  => Service[$service_name],
    require => File[$properties_dir]
  }

  file { "${properties_dir}/admin.aclpolicy":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template($rundeck::acl_template),
    require => File[$properties_dir]
  }

  file { "${properties_dir}/apitoken.aclpolicy":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template('rundeck/apitoken.aclpolicy.erb'),
    require => File[$properties_dir]
  }

  file { "${properties_dir}/profile":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template('rundeck/profile.erb'),
    notify  => Service[$service_name],
    require => File[$properties_dir]
  }

  file { "/etc/sysconfig/rundeckd":
    ensure  => present,
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template('rundeck/sysconfig.erb'),
    notify  => Service[$service_name]
  }

  file { "${properties_dir}/api_tokens.properties":
    owner   => $user,
    group   => $group,
    mode    => '0640',
    content => template('rundeck/api_tokens.properties.erb'),
    notify  => Service[$service_name],
    require => File[$properties_dir]
  }

  ensure_resource('file', ['/etc/facter', '/etc/facter/facts.d'], {'ensure' => 'directory'})

  file { '/etc/facter/facts.d/rundeck_version':
    ensure => present,
    source => 'puppet:///modules/rundeck/rundeck_version',
    owner  => root,
    group  => root,
    mode   => '0755'
  }

  create_resources('rundeck::config::plugin', hiera('rundeck::plugins'))

  create_resources('rundeck::config::project', hiera('rundeck::projects'))

  class { 'rundeck::config::global::framework': } ->
  class { 'rundeck::config::global::project': } ->
  class { 'rundeck::config::global::rundeck_config': } ->
  class { 'rundeck::config::global::ssl': }
}
