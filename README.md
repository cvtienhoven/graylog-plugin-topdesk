# Topdesk Plugin for Graylog

[![Build Status](https://travis-ci.org/cvtienhoven/graylog-plugin-nexmo.svg?branch=master)](https://travis-ci.org/cvtienhoven/graylog-plugin-nexmo)


**Required Graylog version:** 2.4 and later


This plugin enables you to call the Topdesk API to create incidents.


## Installation

[Download the plugin](https://github.com/https://github.com/cvtienhoven/graylog-plugin-nexmo.git/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.

## Use cases

This plugin is useful when you need to create incidents in Topdesk.

## Usage

### Configure the alarm callback

You can configure an alert condition in Graylog and add the `Topdesk Alarm Callback` as the Callback Type. 
In the popup that occurs you can configure the options to send the incident. Not all optional API request 
fields are implemented, but this should get you going. Also some find and replace in the description makes it 
possible to define a template and replace the placeholders with a field value for the first message. You can 
also use some basic HTML tags as described in the  [Topdesk API](https://developers.topdesk.com/documentation/index.html#api-Incident-CreateIncident) 
for the `request` field.


Getting started
---------------

This project is using Maven 3 and requires Java 8 or higher.

* Clone this repository.
* Run `mvn package` to build a JAR file.
* Optional: Run `mvn jdeb:jdeb` and `mvn rpm:rpm` to create a DEB and RPM package respectively.
* Copy generated JAR file in target directory to your Graylog plugin directory.
* Restart the Graylog.

Plugin Release
--------------

We are using the maven release plugin:

```
$ mvn release:prepare
[...]
$ mvn release:perform
```

This sets the version numbers, creates a tag and pushes to GitHub. Travis CI will build the release artifacts and upload to GitHub automatically.
