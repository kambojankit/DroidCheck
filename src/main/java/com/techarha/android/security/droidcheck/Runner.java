package com.techarha.android.security.droidcheck;

import com.techarha.android.security.droidcheck.analyser.StaticAnalyser;

import java.io.*;
import java.util.Properties;

/**
 * INPUT:
 *      APK_FILE_PATH: should be the path where directories benign and malicious are created, which in turn contain directory apks.
 *      apks directory will contain all the sample apks.
 *
 *      BASE_PATH: The path where android sdk is stored.
 *      VERSION: version of the build tools to use, use any of the ones installed on the system.
 *      SDK_FILE_PATH: represents the full path of the 'aapt' tool.
 *
 *      RESULT_PATH: The path to output Results of analysis.
 *
 * Created by ankit on 15/05/15.
 */
public class Runner {

    private static Properties properties = null;

    public static void main(String[] args) {
        String resourceName = "project.properties"; // could also be a constant
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        properties = new Properties();
        try {
            InputStream resourceStream = loader.getResourceAsStream(resourceName);
            properties.load(resourceStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        final String APK_FILE_PATH = properties.getProperty("android.samples.path");

        //ANDROID SDK PATHS
        final String BASE_PATH = properties.getProperty("android.sdk.path");
        final String VERSION = properties.getProperty("android.build-tools.version");
        final String SDK_FILE_PATH = BASE_PATH+"sdk/build-tools/"+VERSION;

        //ANALYSIS OUTPUT PATHS
        final String RESULT_PATH = properties.getProperty("droidcheck.results.path");

        new StaticAnalyser().analysePermissions(SDK_FILE_PATH,RESULT_PATH,APK_FILE_PATH);
    }
}
