package org.graylog;


import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import okhttp3.*;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.alarms.AlertCondition.CheckResult;
import org.graylog2.plugin.alarms.callbacks.AlarmCallback;

import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;

import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.streams.Stream;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Maps;

import org.apache.commons.codec.binary.Base64;

import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class TopdeskAlarmCallback implements AlarmCallback {
	private static final String PRIORITIES_URI = "/tas/api/incidents/priorities";
	private static final String ENTRY_TYPES_URI = "/tas/api/incidents/entry_types";
	private static final String CALL_TYPES_URI = "/tas/api/incidents/call_types";
	private static final String IMPACTS_URI = "/tas/api/incidents/impacts";
	private static final String URGENCIES_URI = "/tas/api/incidents/urgencies";
	private static final String OPERATOR_GROUPS_URI = "/tas/api/operatorgroups";

	public static final MediaType JSON
			= MediaType.parse("application/json; charset=utf-8");

	private static final String ENDPOINT = "endpoint";
	private static final String USERNAME = "username";
	private static final String PASSWORD = "password";
	private static final String LOGIN_MODE = "login_mode";
	private static final String CALLER_EMAIL = "caller_email";
	private static final String PRIORITY = "priority";
	private static final String ENTRY_TYPE = "entry_type";
	private static final String CALL_TYPE = "call_type";
	private static final String OBJECT = "object";
	private static final String IMPACT = "impact";
	private static final String URGENCY = "urgency";
	private static final String OPERATOR_GROUP = "operator_group";

	private static final String SUMMARY = "summary";
	private static final String DESCRIPTION = "description";

	private static final Logger LOG = LoggerFactory.getLogger(TopdeskAlarmCallback.class);
	
	private Configuration configuration;


	@Override
	public void call(Stream stream, CheckResult result) throws AlarmCallbackException {
		String description = configuration.getString(DESCRIPTION);

		description = description.replace("%stream%", stream.getTitle());
		description = description.replace("%triggeredAt%", result.getTriggeredAt().toString());


		if (result.getMatchingMessages().size() > 0) {
			MessageSummary message = result.getMatchingMessages().get(0);
			description.replace("%message%", message.getMessage());

			if (message != null) {
				Map<String, Object> fields = message.getFields();

				Iterator it = fields.entrySet().iterator();
				while (it.hasNext()) {
					Map.Entry pair = (Map.Entry) it.next();
					description = description.replace("%" + pair.getKey() + "%", pair.getValue().toString());
				}
			}
		}

		try {
			OkHttpClient client = getUnsafeOkHttpClient();
			postIncident(client, description);
		} catch (ParseException|IOException e) {
			e.printStackTrace();
		}

	}

	public void postIncident(OkHttpClient client, String description) throws IOException, ParseException {
		String token = login(client);

		post(client, token, description);

		logout(client, token);
	}

	String login(OkHttpClient client) throws IOException{

		String encodedAuth = new String(Base64.encodeBase64((configuration.getString(USERNAME)+":"+configuration.getString(PASSWORD)).getBytes()));


		Request request = new Request.Builder()
				.url(configuration.getString(ENDPOINT)+"/tas/api/login/" + configuration.getString(LOGIN_MODE))
				.addHeader("Authorization", "Basic " + encodedAuth)
				.get()
				.build();
		Response response = client.newCall(request).execute();
		return response.body().string();
	}


	void post(OkHttpClient client, String token, String description) throws IOException, ParseException {
		JSONObject jsonRequest= new JSONObject();

		JSONObject callerLookup = new JSONObject();
		callerLookup.put("email", configuration.getString(CALLER_EMAIL));
		jsonRequest.put("callerLookup", callerLookup);

		jsonRequest.put("briefDescription", configuration.getString(SUMMARY));
		jsonRequest.put("request", description);

		if (configuration.stringIsSet(PRIORITY)) {
			String priorityId = getId(client, token, PRIORITIES_URI, configuration.getString(PRIORITY), "name");
			if (priorityId == null) {
				LOG.error("No priority ID found for name [{}], not creating incident", configuration.getString(PRIORITY));
				return;
			}
			JSONObject priority = new JSONObject();
			priority.put("id", priorityId);
			jsonRequest.put("priority", priority);
		}

		if (configuration.stringIsSet(ENTRY_TYPE)) {
			String entryTypeId = getId(client, token, ENTRY_TYPES_URI, configuration.getString(ENTRY_TYPE), "name");
			if (entryTypeId == null) {
				LOG.error("No entry_type ID found for name [{}], not creating incident", configuration.getString(ENTRY_TYPE));
				return;
			}
			JSONObject entryType = new JSONObject();
			entryType.put("id", entryTypeId);
			jsonRequest.put("entryType", entryType);
		}

		if (configuration.stringIsSet(CALL_TYPE)) {
			String callTypeId = getId(client, token, CALL_TYPES_URI, configuration.getString(CALL_TYPE), "name");
			if (callTypeId == null) {
				LOG.error("No call_type ID found for name [{}], not creating incident", configuration.getString(CALL_TYPE));
				return;
			}
			JSONObject callType = new JSONObject();
			callType.put("id", callTypeId);
			jsonRequest.put("callType", callType);
		}

		if (configuration.stringIsSet(IMPACT)) {
			String impactId = getId(client, token, IMPACTS_URI, configuration.getString(IMPACT), "name");
			if (impactId == null) {
				LOG.error("No impact ID found for name [{}], not creating incident", configuration.getString(IMPACT));
				return;
			}
			JSONObject impact = new JSONObject();
			impact.put("id", impactId);
			jsonRequest.put("impact", impact);
		}

		if (configuration.stringIsSet(URGENCY)) {
			String urgencyId = getId(client, token, URGENCIES_URI, configuration.getString(URGENCY), "name");
			if (urgencyId == null) {
				LOG.error("No urgency ID found for name [{}], not creating incident", configuration.getString(URGENCY));
				return;
			}
			JSONObject urgency = new JSONObject();
			urgency.put("id", urgencyId);
			jsonRequest.put("urgency", urgency);
		}

		if (configuration.stringIsSet(OPERATOR_GROUP)) {
			String operatorGroupId = getId(client, token, OPERATOR_GROUPS_URI+"?name="+configuration.getString(OPERATOR_GROUP), configuration.getString(OPERATOR_GROUP), "groupName");
			if (operatorGroupId == null) {
				LOG.error("No operatorGroup ID found for name [{}], not creating incident", configuration.getString(OPERATOR_GROUP));
				return;
			}
			JSONObject operatorGroup = new JSONObject();
			operatorGroup.put("id", operatorGroupId);
			jsonRequest.put("operatorGroup", operatorGroup);
		}

		JSONObject object = new JSONObject();
		object.put("name", configuration.getString(OBJECT));
		jsonRequest.put("object", object);


		RequestBody body = RequestBody.create(JSON, jsonRequest.toString());

		Request request = new Request.Builder()
				.url(configuration.getString(ENDPOINT)+"/tas/api/incidents/")
				.addHeader("Authorization", "TOKEN id=\"" + token +"\"")
				.post(body)
				.build();

		Response response = client.newCall(request).execute();
		String responseString = response.body().string();
		LOG.info(responseString);
	}

	String getId(OkHttpClient client, String token, String URI, String name, String keyName) throws IOException, ParseException {

		byte[] encodedBytes = Base64.encodeBase64((configuration.getString(USERNAME) + ":" + configuration.getString(PASSWORD)).getBytes());

		Request request = new Request.Builder()
				.url(configuration.getString(ENDPOINT) + URI)
				.addHeader("Authorization", "TOKEN id=\"" + token + "\"")
				.get()
				.build();
		Response response = client.newCall(request).execute();
		JSONParser parser = new JSONParser();
		String jsonString = response.body().string();

		Object object = parser.parse(jsonString);

		JSONArray jsonArray = (JSONArray) object;
		Iterator<JSONObject> iterator = jsonArray.iterator();

		while (iterator.hasNext()) {
			JSONObject current = iterator.next();
			if (name.equals(current.get(keyName))){
				return (String) current.get("id");
			}

		}
		return null;
	}


	String logout(OkHttpClient client, String token) throws IOException{
		byte[] encodedBytes = Base64.encodeBase64((configuration.getString(USERNAME)+":"+configuration.getString(PASSWORD)).getBytes());

		Request request = new Request.Builder()
				.url(configuration.getString(ENDPOINT)+"/tas/api/logout")
				.addHeader("Authorization", "TOKEN id=\"" + token +"\"")
				.get()
				.build();
		Response response = client.newCall(request).execute();
		return response.body().string();
	}


	@Override
	public void checkConfiguration() throws ConfigurationException {

		if (!configuration.stringIsSet(ENDPOINT)) {
			throw new ConfigurationException(ENDPOINT + " is mandatory and must be not be null or empty.");
		}
		if (!configuration.stringIsSet(PASSWORD)) {
			throw new ConfigurationException(PASSWORD + " is mandatory and must be not be null or empty.");
		}

		if (!configuration.stringIsSet(LOGIN_MODE)) {
			throw new ConfigurationException(LOGIN_MODE + " is mandatory and must be not be null or empty.");
		}

		OkHttpClient client;
		String token;

		if (!configuration.stringIsSet(USERNAME)) {
			throw new ConfigurationException(USERNAME + " is mandatory and must be not be null or empty.");
		} else {
			client = getUnsafeOkHttpClient();
			try {
				token = login(client);
			} catch (IOException e) {
				throw new ConfigurationException("Failed to connect to Topdesk. Please check your credentials.");
			}
		}

		try {
			if (configuration.stringIsSet(PRIORITY)) {
				String priorityId = getId(client, token, PRIORITIES_URI, configuration.getString(PRIORITY), "name");
				if (priorityId == null) {
					throw new ConfigurationException( configuration.getString(PRIORITY) + " is not a valid " + PRIORITY);
				}
			}

			if (configuration.stringIsSet(ENTRY_TYPE)) {
				String priorityId = getId(client, token, ENTRY_TYPES_URI, configuration.getString(ENTRY_TYPE), "name");
				if (priorityId == null) {
					throw new ConfigurationException( configuration.getString(ENTRY_TYPE) + " is not a valid " + ENTRY_TYPE);
				}
			}

			if (configuration.stringIsSet(CALL_TYPE)) {
				String priorityId = getId(client, token, CALL_TYPES_URI, configuration.getString(CALL_TYPE), "name");
				if (priorityId == null) {
					throw new ConfigurationException( configuration.getString(CALL_TYPE) + " is not a valid " + CALL_TYPE);
				}
			}

			if (configuration.stringIsSet(IMPACT)) {
				String priorityId = getId(client, token, IMPACTS_URI, configuration.getString(IMPACT), "name");
				if (priorityId == null) {
					throw new ConfigurationException( configuration.getString(IMPACT) + " is not a valid " + IMPACT);
				}
			}

			if (configuration.stringIsSet(URGENCY)) {
				String priorityId = getId(client, token, URGENCIES_URI, configuration.getString(URGENCY), "name");
				if (priorityId == null) {
					throw new ConfigurationException( configuration.getString(URGENCY) + " is not a valid " + URGENCY);
				}
			}

			if (configuration.stringIsSet(OPERATOR_GROUP)) {
				String operatorGroupId = getId(client, token, OPERATOR_GROUPS_URI+"?name="+configuration.getString(OPERATOR_GROUP), configuration.getString(OPERATOR_GROUP), "groupName");
				if (operatorGroupId == null) {
					throw new ConfigurationException( configuration.getString(OPERATOR_GROUP) + " is not a valid " + OPERATOR_GROUP);
				}
			}
		} catch (ParseException|IOException e) {
			throw new ConfigurationException( "Failed to verify configuration: " + e.getMessage());
		}
	}

	@Override
	public Map<String, Object> getAttributes() {
		return Maps.transformEntries(configuration.getSource(), new Maps.EntryTransformer<String, Object, Object>() {
			@Override
			public Object transformEntry(String key, Object value) {
				if (PASSWORD.equals(key)) {
					return "****";
				}
				return value;
			}
		});
	}
	

	@Override
	public String getName() {
		return "Topdesk Alarm Callback";
	}

	@Override
	public ConfigurationRequest getRequestedConfiguration() {
		final ImmutableMap<String, String> login_modes = ImmutableMap.of(
				"person", "person",
				"operator", "operator");

		final ConfigurationRequest configurationRequest = new ConfigurationRequest();
		
		configurationRequest.addField(new TextField(ENDPOINT, "Endpoint", "https://topdesk/",
				"The base url of Topdesk.", ConfigurationField.Optional.NOT_OPTIONAL));

		configurationRequest.addField(new TextField(USERNAME, "Username", "",
				"", ConfigurationField.Optional.NOT_OPTIONAL));

		configurationRequest.addField(new TextField(PASSWORD, "Password", "",
				"", ConfigurationField.Optional.NOT_OPTIONAL, TextField.Attribute.IS_PASSWORD));

		configurationRequest.addField(new DropdownField(LOGIN_MODE, "Login Mode", "person",
				login_modes, ConfigurationField.Optional.NOT_OPTIONAL));


		configurationRequest.addField(new TextField(CALLER_EMAIL, "Caller email", "",
				"", ConfigurationField.Optional.NOT_OPTIONAL));

		configurationRequest.addField(new TextField(PRIORITY, "Priority", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(ENTRY_TYPE, "Entry type", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(CALL_TYPE, "Call type", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(OBJECT, "Object", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(IMPACT, "Impact", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(URGENCY, "Urgency", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(SUMMARY, "Summary", "",
				"", ConfigurationField.Optional.NOT_OPTIONAL));

		configurationRequest.addField(new TextField(OPERATOR_GROUP, "Operator group", "",
				"", ConfigurationField.Optional.OPTIONAL));

		configurationRequest.addField(new TextField(DESCRIPTION, "Desription", "",
				"Full description for the incident. Use %fieldname% placeholders to replace with fields from the first message. Use %stream% for stream name and %triggeredAt% for triggered timestamp.", ConfigurationField.Optional.OPTIONAL));

		return configurationRequest;
	}

	@Override
	public void initialize(Configuration config) {
		this.configuration = config;
	}


	private static OkHttpClient getUnsafeOkHttpClient() {
		try {
			// Create a trust manager that does not validate certificate chains
			final TrustManager[] trustAllCerts = new TrustManager[]{
					new X509TrustManager() {
						@Override
						public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
													   String authType) throws CertificateException {
						}

						@Override
						public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
													   String authType) throws CertificateException {
						}

						@Override
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}
					}
			};

			// Install the all-trusting trust manager
			final SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
			// Create an ssl socket factory with our all-trusting manager
			final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

			return new OkHttpClient.Builder()
					.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0])
					.hostnameVerifier(new HostnameVerifier() {
						@Override
						public boolean verify(String hostname, SSLSession session) {
							return true;
						}
					}).build();

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
}
