package org.graylog;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.AlertCondition.CheckResult;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackConfigurationException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import com.google.common.collect.ImmutableMap;


import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TopdeskAlarmCallbackTest {
	

	private static final ImmutableMap<String, Object> VALID_CONFIG = ImmutableMap.<String, Object> builder()
			.put("endpoint", "https://localhost")
			.put("username", "user")
			.put("password", "pass")
			.put("login_mode", "operator")
			.put("caller_email", "foo@bar.com")
			.put("summary", "summary")
			.put("priority", "priority")
			.put("entry_type", "entry type")
			.put("call_type", "call type")
			.put("object", "object")
			.put("impact", "impact")
			.put("urgency", "urgency")
			.put("operator_group", "operators")
			.put("optional_fields", "optionalFields1:text5:%sha256%")
			.put("description", "Alert raised on stream <b>%stream%</b> at the following time: <b>%triggeredAt%</b>.<br/><br/> Source ip: %src_ip%.")
			.build();


	private static final ImmutableMap<String, Object> INVALID_CONFIG = ImmutableMap.<String, Object> builder()
			.put("endpoint", "https://localhost")
			.put("username", "user")
			.put("password", "pass")
			.put("login_mode", "operator")
			.put("caller_email", "foo@bar.com")
			.put("summary", "summary")
			.put("priority", "priority")
			.put("entry_type", "entry type")
			.put("call_type", "call type")
			.put("object", "object")
			.put("impact", "impact")
			.put("urgency", "urgency")
			.put("operator_group", "operators")
			.put("optional_fields", "test1,test2,test1,test2,test1,test2,test1,test2,test1,test2,test3")
			.put("description", "Alert raised on stream <b>%stream%</b> at the following time: <b>%triggeredAt%</b>.<br/><br/> Source ip: %src_ip%.")
			.build();

	private static final ImmutableMap<String, Object> INVALID_CONFIG_OPTIONAL_FIELDS = ImmutableMap.<String, Object> builder()
			.put("endpoint", "https://localhost")
			.put("username", "user")
			.put("password", "pass")
			.put("login_mode", "operator")
			.put("caller_email", "foo@bar.com")
			.put("summary", "summary")
			.put("priority", "priority")
			.put("entry_type", "entry type")
			.put("call_type", "call type")
			.put("object", "object")
			.put("impact", "impact")
			.put("urgency", "urgency")
			.put("operator_group", "operators")
			.put("optional_fields", "text1:test1,text2:te:st2,text3:test3")
			.put("description", "Alert raised on stream <b>%stream%</b> at the following time: <b>%triggeredAt%</b>.<br/><br/> Source ip: %src_ip%.")
			.build();


	private static final Configuration VALID_CONFIGURATION = new Configuration(VALID_CONFIG);

	private TopdeskAlarmCallback alarmCallback;

	@Before
	public void setUp() {
		alarmCallback = new TopdeskAlarmCallback();
	}

	@Test
	public void testInitialize() throws AlarmCallbackConfigurationException {
		final Configuration configuration = new Configuration(VALID_CONFIG);
		alarmCallback.initialize(configuration);
	}

	@Test
	public void testInitializeInvalid() throws AlarmCallbackConfigurationException {
		final Configuration configuration = new Configuration(INVALID_CONFIG);
		alarmCallback.initialize(configuration);
		try {
			alarmCallback.checkConfiguration();
			fail();
		} catch (ConfigurationException e) {
			System.out.println(e.getMessage());
		}
	}

	@Test
	public void testInitializeInvalidOptionalFields() throws AlarmCallbackConfigurationException {
		final Configuration configuration = new Configuration(INVALID_CONFIG_OPTIONAL_FIELDS);
		alarmCallback.initialize(configuration);
		try {
			alarmCallback.checkConfiguration();
			fail();
		} catch (ConfigurationException e) {
			System.out.println(e.getMessage());
		}
	}

	@Test
	public void testParseOptionalFields(){
		assertEquals(3, alarmCallback.parseOptionalFields("optionalFields1:text1:test1,optionalFields2:text2:test2,optionalFields1:text3:test3,optionalFields1:text4:test4,text5:test5").get("optionalFields1").size());
	}


	@Test
	public void testConfigurationSucceedsWithValidConfiguration()
			throws AlarmCallbackConfigurationException, ConfigurationException {
		alarmCallback.initialize(new Configuration(VALID_CONFIG));
//		try {
//			alarmCallback.checkConfiguration();
//		} catch (ConfigurationException e) {
//			System.out.println(e.getMessage());
//			fail();
//		}
	}

	@Test
	public void testGetName() {
		assertEquals("Topdesk Alarm Callback", alarmCallback.getName());
	}
	

//	@Test
//	public void testCall() throws Exception {
//		DateTime dateTime = new DateTime(2015, 11, 18, 12, 7, DateTimeZone.UTC);
//
//		final Stream stream = mockStream();
//		final AlertCondition.CheckResult checkResult = mockCheckResult(dateTime);//mock(AlertCondition.CheckResult.class);
//		final AlertCondition alertcondition = mockAlertCondition();
//
//		when(checkResult.getTriggeredCondition()).thenReturn(alertcondition);
//
//
//
//		alarmCallback.initialize(VALID_CONFIGURATION);
//		alarmCallback.checkConfiguration();
//
//		alarmCallback.call(stream, checkResult);
//
//		//verify(client).submitMessage(Mockito.any(TextMessage.class));
//	}



	private AlertCondition mockAlertCondition() {
		final String alertConditionId = "alertConditionId";
		final AlertCondition alertCondition = mock(AlertCondition.class);
		when(alertCondition.getId()).thenReturn(alertConditionId);
		when(alertCondition.getDescription()).thenReturn("alert description");
		when(alertCondition.getBacklog()).thenReturn(1);
		return alertCondition;
	}

	private Stream mockStream() {
		// final String alertConditionId = "alertConditionId";
		final Stream stream = mock(Stream.class);
		when(stream.getTitle()).thenReturn("Stream title");
		return stream;
	}

	private CheckResult mockCheckResult(DateTime dateTime){
		final CheckResult result = mock(CheckResult.class);
		List<MessageSummary> messages = new ArrayList<MessageSummary>();

		Message message1 = mock(Message.class);
		when(message1.getId()).thenReturn("test_id1");
		when(message1.getSource()).thenReturn("test_source1");
		when(message1.getMessage()).thenReturn("test_message1");
		Map<String, Object> fields = new HashMap<String, Object>();
		fields.put("src_ip", "123.123.321.321");
		fields.put("sha256", "soidjfvoisdjfg0983sovsdsg");


		when(message1.getFields()).thenReturn(fields);
		when(message1.getFieldsEntries()).thenCallRealMethod();


		Message message2 = mock(Message.class);
		when(message2.getId()).thenReturn("test_id2");
		when(message2.getSource()).thenReturn("test_source2");
		when(message2.getMessage()).thenReturn("test_message2");
		when(message2.getFields()).thenReturn(fields);
		when(message2.getFieldsEntries()).thenCallRealMethod();

		MessageSummary messageSummary1 = new MessageSummary("index1", message1);
		messages.add(messageSummary1);

		MessageSummary messageSummary2 = new MessageSummary("index2", message2);
		messages.add(messageSummary2);

		when(result.getMatchingMessages()).thenReturn(messages);
		when(result.getTriggeredAt()).thenReturn(dateTime);
		when(result.getResultDescription()).thenReturn("Result description");
		return result;
	}
}
