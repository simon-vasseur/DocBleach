package xyz.docbleach.http_server;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.DefaultBleach;
import xyz.docbleach.api.exception.BleachException;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static spark.Spark.*;

import java.io.*;
import java.util.Base64;

public class Main {

    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    private static final int HTTP_BAD_REQUEST = 400;
    private static final int INTERNAL_SERVER_ERROR = 500;

    interface Validable {
        boolean isValid();
    }

    @Data
    static class PostPayload {
        private String File;
        
        public boolean isValid() {
            return File != null && !File.isEmpty();
        }
    }

    @Data
    static class Sanitized {
        private Boolean Status;
        private String Error;
        private String File;
        private int OriginalFileSize;
        private int Base64Size;
    }

    public static void main(String[] args) {

        port(getPortNumber());
        
        int maxThreads = 20;
        int minThreads = 10;
        int timeOutMillis = 60000;
        threadPool(maxThreads, minThreads, timeOutMillis);

        post("/sanitize", (request, response) -> {
            
            try {
                PostPayload payload = getPayload(request.body());
                if (!payload.isValid()) {
                    response.status(HTTP_BAD_REQUEST);
                    return "";
                }
                Sanitized sanitized = sanitize(payload.getFile());
                response.status(200);
                response.type("application/json");
                return dataToJson(sanitized);
            } catch (JsonParseException | JsonMappingException ex) {
                response.status(HTTP_BAD_REQUEST);
                return "";
            } catch (BleachException ex) {
                LOGGER.warn(String.format("DocBleach exception: %s", ex.toString()));
                response.status(INTERNAL_SERVER_ERROR);
                return "";
            } catch (Exception ex) {
                LOGGER.warn(String.format("Unknown exception: %s", ex.toString()));
                response.status(INTERNAL_SERVER_ERROR);
                return "";
            }
        });

        after((request, response) -> {
            LOGGER.info(String.format(
                "%s %s => %s %d",
                request.requestMethod(),
                request.uri(),
                request.protocol(),
                response.status()
            ));
        });
    }

    private static PostPayload getPayload(String body) throws IOException, 
            JsonParseException, JsonMappingException {
                
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        PostPayload payload = mapper.readValue(body, PostPayload.class);
        return payload;
    }
    
    private static Sanitized sanitize(String content) throws BleachException {
        
        BleachSession session = new BleachSession(new DefaultBleach());
        byte[] decoded = Base64.getDecoder().decode(content);

        InputStream in = new ByteArrayInputStream(decoded);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        Sanitized sanitized = new Sanitized();
        session.sanitize(in, out);

        if (out.size() == 0) {
            throw new BleachException("Sanitized file is empty");
        }
        
        String encoded = Base64.getEncoder().encodeToString(out.toByteArray());
        sanitized.setFile(encoded.toString());
        sanitized.setOriginalFileSize(out.size());
        sanitized.setBase64Size(encoded.length());
        sanitized.setStatus(true);

        if (session.threatCount() == 0) {
            sanitized.setError("The file was already safe, so I've just copied it over");
        } else {
            sanitized.setError(String.format(
                "Sanitized file has been saved, %d potential threat(s) removed.", 
                session.threatCount()
            ));
        }
        LOGGER.info(sanitized.getError());
        
        return sanitized;
    }
    
    private static int getPortNumber() {
        int port = 8080;
        String PORT = System.getenv("PORT");
        if (PORT != null && !PORT.isEmpty()) {
            try {
                port = Integer.valueOf(PORT);
            } catch (NumberFormatException e) {
                LOGGER.error("Invalid PORT defined in environment, falling back to 8080.");
            }
        }
        return port;
    }

    private static String dataToJson(Object data) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            StringWriter sw = new StringWriter();
            mapper.writeValue(sw, data);
            return sw.toString();
        } catch (IOException e){
            throw new RuntimeException("IOException from a StringWriter?");
        }
    }
}
