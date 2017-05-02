package xyz.docbleach.http_server;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigException;
import org.apache.tika.Tika;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.DefaultBleach;
import xyz.docbleach.api.exception.BleachException;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static spark.Spark.*;

import java.io.*;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


public class Main {

    private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);

    private static final int HTTP_BAD_REQUEST = 400;
    private static final int INTERNAL_SERVER_ERROR = 500;
    
    private static final Tika tika = new Tika();
    private static final Config config = ConfigFactory.load();
    private static final List<String> blackListedZipFileExtensions = config.getStringList("blackListedExtensions");

    interface Validable {
        boolean isValid();
    }

    @Data
    static class PostPayload {
        
        @JsonProperty("FileName")
        private String FileName;
        
        @JsonProperty("OriginalFileSize")
        private Integer OriginalFileSize;
        
        @JsonProperty("Base64Size")
        private Integer Base64Size;
        
        @JsonProperty("ContentType")
        private String ContentType;
        
        @JsonProperty("MessageId")
        private String MessageId;
        
        @JsonProperty("File")
        private String File;
        
        public boolean isValid() {
            return File != null && !File.isEmpty() && MessageId != null && !MessageId.isEmpty();
        }
    }

    @Data
    static class Sanitized {
        
        @JsonProperty("Status")
        private Boolean Status;
        
        @JsonProperty("Error")
        private String Error;
        
        @JsonProperty("File")
        private String File;
        
        @JsonProperty("OriginalFileSize")
        private int OriginalFileSize;
        
        @JsonProperty("Base64Size")
        private int Base64Size;
    }

    public static void main(String[] args) {

        port(getPortNumber());
        
        int maxThreads = 50;
        int minThreads = 20;
        int timeOutMillis = 60000;
        threadPool(maxThreads, minThreads, timeOutMillis);

        post("/v1/synchronous/tasks", (request, response) -> {

            try {
                PostPayload payload = getPayload(request.body());
                if (!payload.isValid()) {
                    response.status(HTTP_BAD_REQUEST);
                    return "";
                }
                LOGGER.info(String.format("Processing %s", payload.getMessageId()));
                Sanitized sanitized = sanitize(payload.getFile());
                response.status(200);
                response.type("application/json");
                return dataToJson(sanitized);
            } catch (JsonParseException | JsonMappingException ex) {
                response.status(HTTP_BAD_REQUEST);
                return "";
            } catch (BleachException | IOException ex) {
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
        PostPayload payload = mapper.readValue(body, PostPayload.class);
        return payload;
    }
    
    private static Sanitized sanitize(String content) throws BleachException, IOException {
        
        BleachSession session = new BleachSession(new DefaultBleach());
        byte[] decoded = Base64.getDecoder().decode(content);

        InputStream in = new ByteArrayInputStream(decoded);
        String mimeType = tika.detect(in);

        if (mimeType == "application/zip") {
            LOGGER.info("Zip file detected");
            in = purgeZipFile(in);
        }

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

    private static InputStream purgeZipFile(InputStream zipContent) throws IOException{
            
        ZipInputStream zis = new ZipInputStream(zipContent);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(bos);
        byte[] buffer = new byte[1024];
        
        ZipEntry entry = zis.getNextEntry();

        while(entry != null) {
            String fileName = entry.getName();
            String extension = getExtension(fileName);
            
            if(blackListedZipFileExtensions.contains(extension)){
                LOGGER.info(String.format(
                    "Removing %s from zip file -> blacklisted extension", 
                    fileName
                ));
            } else {
                ZipEntry newEntry = new ZipEntry(entry.getName());
                zos.putNextEntry(newEntry);

                int len;
                while ((len = zis.read(buffer)) > 0) {
                    zos.write(buffer, 0, len);
                }
                zos.closeEntry();
            }
            zis.closeEntry();
            entry = zis.getNextEntry();
        }
        
        zis.close();
        zos.close();

        return new ByteArrayInputStream(bos.toByteArray());
    }

    private static String getExtension(String fileName) {

        String extension = "";

        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            extension = fileName.substring(i+1);
        }
        return extension.toLowerCase();
    }

    private static int getPortNumber() {
        int port = 8080;
        try {
            port = config.getInt("bindPort");
        } catch (ConfigException e) {
            LOGGER.error("Invalid PORT defined in environment, falling back to 8080.");
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
