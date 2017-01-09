package burp;

import com.codemagi.burp.Utils;
import com.codemagi.burp.parser.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.models.HttpMethod;
import io.swagger.models.Model;
import io.swagger.models.Operation;
import io.swagger.models.Path;
import io.swagger.models.Swagger;
import io.swagger.models.apideclaration.ApiDeclaration;
import io.swagger.models.parameters.AbstractSerializableParameter;
import io.swagger.models.parameters.BodyParameter;
import io.swagger.models.parameters.Parameter;
import io.swagger.parser.SwaggerParser;
import io.swagger.util.Json;

import io.swagger.models.properties.ArrayProperty;
import io.swagger.models.properties.Property;
import io.swagger.models.properties.RefProperty;
import io.swagger.models.resourcelisting.ResourceListing;
import io.swagger.parser.SwaggerCompatConverter;
import io.swagger.parser.util.SwaggerDeserializationResult;
import io.swagger.report.MessageBuilder;
import io.swagger.transform.migrate.ApiDeclarationMigrator;
import io.swagger.transform.migrate.ResourceListingMigrator;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;

public class Parser {

	public static IExtensionHelpers helpers;
	public static IBurpExtenderCallbacks callbacks;
	public static IHttpRequestResponse httpRequestResponse;
	public static List<String> headers;
	//contains the (HashMap) structure of our built models
	private final Map<String, Map<String, Object>> hashModels = new HashMap<>();
	private Swagger swagger;
	private final SwaggerParserTab tab;

	public Parser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, SwaggerParserTab tab) {
		Parser.callbacks = callbacks;
		Parser.helpers = helpers;
		this.tab = tab;
	}

	public int parseSwagger(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) {
		callbacks.printOutput("parseSwagger");
		httpRequestResponse = requestResponse;
		byte[] response = requestResponse.getResponse();

		if (response == null) {
			IHttpRequestResponse request = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
			response = request.getResponse();
		}
		if (response == null) {
			JOptionPane.showMessageDialog(tab.getUiComponent().getParent(), "Can't Read Response", "Error", JOptionPane.ERROR_MESSAGE);
			return -1;
		}

		IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
		headers = requestInfo.getHeaders();
		callbacks.printOutput("got headers");

		URL url = requestInfo.getUrl();
		callbacks.printOutput("url: " + url.toString());

		String requestName = url.getHost();
		callbacks.printOutput("domain: " + requestName);

		try {
			String responseBody = new String(Utils.getResponseBody(response, helpers));
			callbacks.printOutput("RESPONSE BODY ----- \n" + responseBody);
			SwaggerParser sp = new SwaggerParser();
			callbacks.printOutput("sp: " + sp);
			
			SwaggerDeserializationResult sdr = sp.readWithInfo(responseBody);
			callbacks.printOutput("sdr: " + sdr);
			callbacks.printOutput("sdr: " + sdr.getMessages());
			
			swagger = sp.parse(responseBody);
			callbacks.printOutput("swagger: " + swagger);
			
			if (swagger == null) {
				//maybe its an older version of the swagger spec...
				MessageBuilder messages = new MessageBuilder();

				ResourceListing resourceListing = readResourceListing(responseBody, messages);

				ApiDeclaration apiDeclaration = readDeclaration(responseBody, messages);
				List<ApiDeclaration> apis = new ArrayList<>();
				apis.add(apiDeclaration);
								
				swagger = new SwaggerCompatConverter().convert(resourceListing, apis);
			}
			
			callbacks.printOutput("swagger: " + swagger.getHost() + swagger.getBasePath());

			//generate the models (JSON request body)
			List<Object> allModels = new ArrayList<>();
			generateModels(swagger, allModels);

			//initialize the GUI tab to display the results
			SwaggerTab swaggerTab = tab.createTab(requestName);

			//create the subtabs
			Map<String, Path> paths = swagger.getPaths();
			for (String pathName : paths.keySet()) {
				Path path = paths.get(pathName);

				callbacks.printOutput("path: " + pathName);
				callbacks.printOutput(Json.pretty(path));

				URL pathUrl = new URL(url.getProtocol(), url.getHost(), url.getPort(), pathName);

				Map<HttpMethod, Operation> operations = path.getOperationMap();
				for (HttpMethod method : operations.keySet()) {
					String operationName = method.name();
					callbacks.printOutput("  method: " + operationName);
					callbacks.printOutput(Json.pretty(method));

					Operation op = operations.get(method);
					callbacks.printOutput("  op: " + op);
					callbacks.printOutput(Json.pretty(op));

					//create a request for this operation
					HttpRequest request = new HttpRequest(pathUrl, operationName);
					request.setHeader("Content-Type", Utils.getFirst(op.getConsumes()));
					request.setHeader("Accept", Utils.getFirst(op.getProduces()));
					request.setHeader("Origin", url.toString());

					//add the params
					List<Parameter> parameters = op.getParameters();
					for (Parameter p : parameters) {
						callbacks.printOutput("    param: " + Json.pretty(p));
						switch (p.getIn()) {
							case "query":
								request.setParameter(p.getName(), getDefaultValue(p));
								break;
							case "path":
								String requestPath = request.getPath();
								request.setPath(requestPath.replace("{" + p.getName() + "}", getDefaultValue(p)));
								break;
							case "body":
								request.setBody(getDefaultValue(p));
								break;
							case "header":
								request.setHeader(p.getName(), getDefaultValue(p));
								break;
							case "form":
								request.setParameter(p.getName(), getDefaultValue(p));
								request.convertToPost();
								break;
						}
					}

					callbacks.printOutput("REQUEST: " + request.toString());

					swaggerTab.addEntry(new SwaggerEntry(pathName, request.getBytes(), operationName, op.getDescription(), requestResponse, Json.pretty(op)));
				}
			}
		} catch (Exception e) {
			BurpExtender.getInstance().printStackTrace(e);
		}
		return 0;
	}
	
    public ResourceListing readResourceListing(String input, MessageBuilder messages) {
        ResourceListing output = null;
        JsonNode jsonNode;
        try {
			jsonNode = Json.mapper().readTree(input);

			if (jsonNode.get("swaggerVersion") == null) {
                return null;
            }
            ResourceListingMigrator migrator = new ResourceListingMigrator();
            JsonNode transformed = migrator.migrate(messages, jsonNode);
            output = Json.mapper().convertValue(transformed, ResourceListing.class);
        } catch (java.lang.IllegalArgumentException e) {
            return null;
        } catch (Exception e) {
            BurpExtender.getInstance().printStackTrace(e);
        }
        return output;
    }

	public ApiDeclaration readDeclaration(String input, MessageBuilder messages) {
        ApiDeclaration output = null;
        try {
            JsonNode jsonNode = Json.mapper().readTree(input);

            // this should be moved to a json patch
            if (jsonNode.isObject()) {
                ((ObjectNode) jsonNode).remove("authorizations");
            }

            ApiDeclarationMigrator migrator = new ApiDeclarationMigrator();
            JsonNode transformed = migrator.migrate(messages, jsonNode);
            output = Json.mapper().convertValue(transformed, ApiDeclaration.class);
        } catch (java.lang.IllegalArgumentException e) {
            return null;
        } catch (Exception e) {
            BurpExtender.getInstance().printStackTrace(e);
        }
        return output;
    }

	private String getDefaultValue(Parameter p) {
		callbacks.printOutput("***** getDefaultValue ***** Parameter " + p);
		if (p == null) {
			return "";
		}

		if (p instanceof AbstractSerializableParameter) {
			String type = ((AbstractSerializableParameter) p).getType();

			switch (type) {
				case "integer":
					return "1234";
				case "long":
					return "2147483648";
				case "float":
					return "1.23";
				case "double":
					return "3.149";
				case "string":
					return "aeiou";
				case "byte":
					return "1";
				case "boolean":
					return "true";
				case "date":
					return "2000-01-23";
				case "dateTime":
					return "2000-01-23T04:56:07.000+00:00";
				case "array":
					return "1,2,3";
			}
		} else if (p instanceof BodyParameter) {
			Model schema = ((BodyParameter) p).getSchema();
			callbacks.printOutput("BodyParameter: " + Json.pretty(schema));
			String datatype = getDatatypeName(schema.getReference());
			return Json.pretty(hashModels.get(datatype));
		}
		return "";
	}

	private Map<String, Object> createModelHash(String modelName, Model model) {
		callbacks.printOutput("***** createModelHash ***** modelName " + modelName + " Model: " + model);

		Map<String, Object> output = new HashMap<>();

		//if we don't have a valid model, just return an empty output
		if (model == null) return output;
		
		//if we already have this model cached, return it
		callbacks.printOutput("hashModels: " + hashModels);
		if (hashModels.containsKey(modelName)) {
			callbacks.printOutput("CACHE HIT!");
			
			output = hashModels.get(modelName);
			callbacks.printOutput(Json.pretty(output));
			return output;
		}
		
		//first add a dummy value to the hashModels in case this is self-referential
		hashModels.put(modelName, output);

		//get the properties from the model
		Map<String, Property> properties = model.getProperties();
		if (properties == null) {
			return output;
		}

		//for each property, add name and default value to the hash structure
		for (String propertyName : properties.keySet()) {
			Property prop = properties.get(propertyName);
			output.put(propertyName, getDefaultValue(prop, modelName));
		}

		//finally, cache this representation
		hashModels.put(modelName, output);

		return output;
	}

	private Object getDefaultValue(Property prop, String modelName) {
		callbacks.printOutput("***** getDefaultValue ***** Property " + prop + " Model: " + modelName);
		if (prop == null) {
			return "";
		}
		
		if (prop instanceof RefProperty) {
			//a reference property is a reference to another model object
			//so get a reference to the object type
			RefProperty r = (RefProperty) prop;
			String datatype = r.get$ref();
			datatype = getDatatypeName(datatype);
			callbacks.printOutput("RefProperty! " + datatype);
			
			//check for self-referential
			if (datatype.equals(modelName)) {
				return new Object();

			} else if (hashModels.containsKey(datatype)) {
				//we have already constructed this data type as a hashmodel, 
				//add it to the output
				Object hashModel = hashModels.get(datatype);
				return hashModel;

			} else {
				//we don't yet have a hashmodel, so construct one
				Model refModel = getModel(datatype);
				Map<String, Object> hashModel = createModelHash(datatype, refModel);
				return hashModel;

			}
		} else if (prop instanceof ArrayProperty) {
			//an array property is an array of some other type of property
			callbacks.printOutput("ArryProperty! " + prop);
			ArrayProperty a = (ArrayProperty) prop;

			//get the type of object this array holds
			Property arrayItem = a.getItems();

			//get the default value for the object in the array
			Object arrayIemValue = getDefaultValue(arrayItem, modelName);

			//construct an array containing the item 
			Object[] arrayModel = {arrayIemValue};

			//add it to the output
			return arrayModel;

		} else {
			//we are dealing with a primitive type, so just get a default value
			String type = prop.getType();

			switch (type) {
				case "integer":
					return 1234;
				case "long":
					return 2147483648l;
				case "float":
					return 1.23f;
				case "double":
					return 3.149d;
				case "string":
					if ("date-time".equals(prop.getFormat())) {
						return "2016-12-15 13:25:30:00";
					} else if ("date".equals(prop.getFormat())) {
						return "2016-12-15";
					} else {
						return "aeiou";
					}
				case "byte":
					return (byte) 1;
				case "boolean":
					return true;
				case "date":
					return new Date();
				case "dateTime":
					return new Date();
			}
		}

		//if all else fails...
		return "";
	}

	private String getDatatypeName(String datatype) {
		if (datatype.indexOf("#/definitions/") == 0) {
			datatype = datatype.substring("#/definitions/".length());
		}
		return datatype;
	}

	private Model getModel(String modelName) {
		final Map<String, Model> definitions = swagger.getDefinitions();
		return definitions.get(modelName);
	}

	private void generateModels(Swagger swagger, List<Object> allModels) {
		callbacks.printOutput("***** generateModels *****");

		final Map<String, Model> definitions = swagger.getDefinitions();
		callbacks.printOutput("definitions: " + definitions);
		if (definitions == null) {
			return;
		}

		Set<String> modelKeys = definitions.keySet();
		callbacks.printOutput("modelKeys: " + StringUtils.join(definitions, ","));

		// process models only
		for (String modelName : modelKeys) {
			callbacks.printOutput("PROCESSING -------------------");
			callbacks.printOutput(modelName);

			try {
				Model model = definitions.get(modelName);
				callbacks.printOutput("MODEL -----------------------\n");
				callbacks.printOutput(Json.pretty(model));

				//construct a hashmap representation of our model which can be output as JSON
				Map<String, Object> modelHash = createModelHash(modelName, model);
				callbacks.printOutput("JSON ------------------------ " + modelName + "\n");
				try {
					callbacks.printOutput(Json.pretty(modelHash));
				} catch (Exception e) {
					BurpExtender.getInstance().printStackTrace(e);
				}

			} catch (Exception e) {
				callbacks.printError("Could not process model '" + modelName + "'" + ".Please make sure that your schema is correct!");
				BurpExtender.getInstance().printStackTrace(e);
				throw new RuntimeException("Could not process model '" + modelName + "'" + ".Please make sure that your schema is correct!", e);
			}
		}
	}
}
