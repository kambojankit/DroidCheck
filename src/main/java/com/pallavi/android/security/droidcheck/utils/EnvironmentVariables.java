package com.pallavi.android.security.droidcheck.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Created by ankit on 06/06/15.
 */
public class EnvironmentVariables {
    private String androidSDKFilePath;
    private String sdkBuildToolsFilePath;
    private String resultPath;
    private String sampleAPKFilePath;

    private String createAVDCommand;
    private String avdName;
    private String startEmulatorCommand;
    private String apkInstallCommand;
    private String apkLaunchCommand;
    private String checkAVDExists;

    public EnvironmentVariables() {
        load();
    }

    public static EnvironmentVariables prepareEnvironment() {
        return new EnvironmentVariables();
    }

    private void load() {
        Properties properties;
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

        sampleAPKFilePath = properties.getProperty("android.samples.path");

        //ANDROID SDK PATHS
        androidSDKFilePath = properties.getProperty("android.sdk.path");
        final String VERSION = properties.getProperty("android.build-tools.version");
        sdkBuildToolsFilePath = androidSDKFilePath + "build-tools/" + VERSION;

        //ANALYSIS OUTPUT PATHS
        resultPath = properties.getProperty("droidcheck.results.path");

        //LOAD commands
        avdName = properties.getProperty("android.avd.name");
        createAVDCommand = String.format(properties.getProperty("android.avd.create.command"), avdName, properties.getProperty("android.avd.targetID"));
        checkAVDExists = properties.getProperty("android.avd.check_exists.command");
        startEmulatorCommand = String.format(properties.getProperty("android.emulator.run.command"), properties.getProperty("android.avd.name"));
        apkInstallCommand = properties.getProperty("android.apk.install.command");
        apkLaunchCommand = properties.getProperty("android.apk.launch.command");
    }

    public String getAndroidSDKFilePath() {
        return androidSDKFilePath;
    }

    public String getSdkBuildToolsFilePath() {
        return sdkBuildToolsFilePath;
    }

    public String getResultPath() {
        return resultPath;
    }

    public String getSampleAPKFilePath() {
        return sampleAPKFilePath;
    }

    public String getCreateAVDCommand() {
        return createAVDCommand;
    }

    public String getAvdName() {
        return avdName;
    }

    public String getStartEmulatorCommand() {
        return startEmulatorCommand;
    }

    public String getApkInstallCommand() {
        return apkInstallCommand;
    }

    public String getApkLaunchCommand() {
        return apkLaunchCommand;
    }

    public String getCheckAVDExists() {
        return checkAVDExists;
    }

}
