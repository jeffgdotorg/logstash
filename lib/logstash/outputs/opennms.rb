# encoding: utf-8
require "logstash/namespace"
require "logstash/outputs/base"

# The OpenNMS output sends log data to OpenNMS as events via the
# XML/TCP listener of OpenNMS' Eventd.
#
# For this output to work, your event _must_ have the following Logstash event field
# with a true value:
#
#  * `opennms\_event`
#
# These Logstash event fields are supported, but optional:
#
#  * `opennms\_host` (overrides `opennms\_host` configuration option)
#  * `opennms\_uei` (overrides `opennms\_uei` configuration option)
#  * `opennms\_eventsource` (overrides `opennms\_eventsource` configuration option)
#  * `opennms\_interface`
#  * `opennms\_service`
#  * `opennms\_severity` (overrides `opennms\_severity` configuration option)
#
# There are two configuration options:
#
#  * `opennms\_host` - The IP address or hostname, and optional port number,
#    of the OpenNMS server to whose Eventd XML-TCP listener we should connect.
#    This option is required.
#  * `opennms\_severity` - Specifies the severity of the events to be sent. Defaults
#    to Indeterminate and can be overriden by setting the "opennms\_severity" field to
#    one of "Indeterminate", "Normal", "Warning", "Minor", "Major", or "Critical".
#
#     output{
#       if [message] =~ /(error|ERROR|CRITICAL)/ {
#         opennms {
#           # your config here
#         }
#       }
#     }
#
class LogStash::Outputs::OpenNMS < LogStash::Outputs::Base

  config_name "opennms"
  milestone 1

  EXCLUDE_ALWAYS = [ "@timestamp", "@version" ]

  # The hostname of your OpenNMS server. Port may be specified separately
  # if needed via `opennms_port`
  #
  # For example:
  #
  #     "127.0.0.1"
  config :opennms_host, :validate => :string, :required => true

  #
  # The port number of your OpenNMS server's Eventd TCP listener.
  config :opennms_port, :validate => :number, :default => 5817

  # Interval between reconnect attempts to OpenNMS Eventd listener.
  config :reconnect_interval, :validate => :number, :default => 2
  #
  # Should events be resent on failure?
  config :resend_on_failure, :validate => :boolean, :default => false

  #
  # The universal event identifier (UEI) of the event to send to OpenNMS. Must
  # begin with the string "uei." but the rest is free-form. Note that an event
  # definition for this UEI must exist on the OpenNMS server for useful events
  # to be created.
  config :opennms_uei, :validate => :string, :default => "uei.opennms.org/external/logstash/defaultEvent"

  #
  # The event source identifier for the events sent to OpenNMS.
  config :opennms_eventsource, :validate => :string, :default => "logstash"

  # The OpenNMS event severity. Must be one of "Indeterminate", "Normal",
  # "Warning", "Minor", "Major", or "Critical". Defaults to "Warning".
  config :opennms_severity, :validate => [ "Indeterminate", "Normal", "Warning", "Minor", "Major", "Critical" ], :default => "Indeterminate"
  #
  # Include only regex-matched field names in output event params.
  config :include_fields, :validate => :array, :default => [ ".*" ]

  # Exclude regex-matched field names from output event params, by default
  # exclude unresolved %{field} strings.
  config :exclude_fields, :validate => :array, :default => [ "%\{[^}]+\}" ]

  public
  def register
    require 'rexml/document'
    require 'rexml/cdata'
    @include_fields.collect!{|regexp| Regexp.new(regexp)}
    @exclude_fields.collect!{|regexp| Regexp.new(regexp)}

    connect
  end # def register

  public
  def connect
    # TODO(jeffgdotorg): Test error cases. Catch exceptions. Stop cargo-culting sissel's work.
    begin
      @socket = TCPSocket.new(@opennms_host, @opennms_port)
    rescue Errno::ECONNREFUSED => e
      @logger.warn("Connection refused to OpenNMS server, sleeping...",
                   :host => @opennms_host, :port => @opennms_port)
      sleep(@reconnect_interval)
      retry
    end
  end # def connect

  public
  def receive(event)
    return unless output?(event)

    inUei = event["opennms_uei"]
    inSource = event["opennms_eventsource"]
    inInterface = event["opennms_interface"]
    inService = event["opennms_service"]
    inSeverity = event["opennms_severity"]

    outEventsXML = REXML::Document.new
    outLog = outEventsXML.add_element "log"
    outEvents = outLog.add_element "events"
    outEvent = outEvents.add_element "event"
    outUei = outEvent.add_element "uei"
    if inUei
      outUei.text = inUei
    else
      outUei.text = @opennms_uei
    end
    outSource = outEvent.add_element "source"
    if inSource
      outSource.text = inSource
    else
      outSource.text = @opennms_eventsource
    end
    if inInterface
      outInterface = outEvent.add_element "interface"
      outInterface.text = inInterface
    end
    if inService
      outService = outEvent.add_element "service"
      outService.text = inService
    end
    outParms = outEvent.add_element "parms"
    event.to_hash.each do |inParmName, inParmValue|
      next if EXCLUDE_ALWAYS.include?(inParmName)
      next unless @include_fields.empty? || @include_fields.any? { |regexp| inParmName.match(regexp) }
      next if @exclude_fields.any? {|regexp| inParmName.match(regexp)}
      outParm = outParms.add_element "parm"
      outParmName = outParm.add_element "parmName"
      outParmName.text = REXML::CData.new(inParmName)
      outParmValue = outParm.add_element "value"
      outParmValue.attributes["type"] = "string"
      outParmValue.attributes["encoding"] = "text"
      outParmValue.text = REXML::CData.new(inParmValue.to_s.delete("\000"))
    end
    outSeverity = outEvent.add_element "severity"
    if inSeverity
      outSeverity.text = inSeverity
    else
      outSeverity.text = @opennms_severity
    end
    
    @logger.debug("Sending OpenNMS event log", :eventlog => outEventsXML.to_s, :host => @opennms_host, :port => @opennms_port)
    # Catch exceptions like ECONNRESET and friends, reconnect on failure.
    # TODO(jeffgdotorg): Test error cases. Catch exceptions. Stop cargo-culting sissel's code.
    begin
      @socket.puts(outEventsXML)
    rescue Errno::EPIPE, Errno::ECONNRESET => e
      @logger.warn("Connection to OpenNMS Eventd TCP listener died",
                   :exception => e, :host => @opennms_host, :port => @opennms_port)
      sleep(@reconnect_interval)
      connect
      retry if @resend_on_failure
    end
  end # def receive
end # class LogStash::Outputs::OpenNMS
