package org.talend.components.playground.cxf.rt.rs.client;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class ResourcesUtils {

    public static String loadResource(String name) {
        InputStream resourceAsStream = ResourcesUtils.class.getResourceAsStream(name);
        String content = getString(resourceAsStream);
        return content;
    }

    public static String getString(InputStream resourceAsStream) {
        InputStreamReader isr = new InputStreamReader(resourceAsStream, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr);
        String content = br.lines().collect(Collectors.joining("\n"));
        return content;
    }

}