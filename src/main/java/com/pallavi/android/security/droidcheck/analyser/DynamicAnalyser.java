package com.pallavi.android.security.droidcheck.analyser;

import com.android.chimpchat.ChimpChat;
import com.android.chimpchat.ChimpManager;
import com.android.chimpchat.core.IChimpDevice;
import com.android.ddmlib.ShellCommandUnresponsiveException;
import com.pallavi.android.security.droidcheck.domain.StaticAndroidData;
import com.pallavi.android.security.droidcheck.utils.EnvironmentVariables;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Created by ankit on 28/05/15.
 */
public class DynamicAnalyser {

    public static final int WAIT_AFTER_INSTALL = 2 * 60 * 1000;
    public static final int WAIT_AFTER_REMOVAL = 1 * 40 * 1000;
    private int timeout = 40*000;

    public void analyse(EnvironmentVariables env, Map<String, List<StaticAndroidData>> staticDataMap) {
        IChimpDevice mDevice = initializeTestingEnvironment(env);

        List<StaticAndroidData> benignSampleDataList = staticDataMap.get("benign");
        List<StaticAndroidData> maliciousSampleDataList = staticDataMap.get("malicious");

        analyseMaliciousSamples(env, mDevice, maliciousSampleDataList);

        //3. now pick the apk from the apk file path and install it to the device.
        analyseBenignSamples(env, mDevice, benignSampleDataList);

        mDevice =null;
    }

    private void analyseMaliciousSamples(EnvironmentVariables env, IChimpDevice mDevice, List<StaticAndroidData> maliciousSampleDataList) {
        for(StaticAndroidData data : maliciousSampleDataList) {
            try {
                if(!(data.getPackageName()==null || data.getActivityName() == null)){
                    System.out.println("Starting Now");
                    //check if app already installed
                    String deviceAPKPath = mDevice.shell(String.format("adb shell pm path %s", data.getPackageName()), timeout);
                    System.out.println("Checking if package " + data.getPackageName() + "is already installed");

                    mDevice.wake();
                    if (!deviceAPKPath.startsWith("package:")) {
                        //application is not installed
                        mDevice.installPackage(data.getAndroidSample().getPathToApk());
                        System.out.println("Installed Package: " + data.getPackageName());
                    }

                    //start activity
                    String startActivityCommand = "adb shell am start -a android.intent.action.MAIN -n " + data.getPackageName() + "/" + data.getActivityName();
                    String result = mDevice.shell(startActivityCommand, timeout);
                    System.out.println("starting activity: " + result);

                    mDevice.wake();

                    String processIDCommand = "adb shell ps | grep " + data.getPackageName();
                    System.out.println("command is: " + processIDCommand);

                    String outputShell = mDevice.shell(processIDCommand, timeout);
                    System.out.println("command is: " + outputShell);
                    String[] str = outputShell.split("\\s+");
                    String processID = str[1];
                    System.out.println("Process ID is: " + processID);

                    mDevice.wake();
                    //runStrace command on the package and output data to predefined location on disk
                    String fileName = data.getAndroidSample().getName() + ".txt";
                    String straceCommand = "adb shell strace -cvf -p " + processID + " -o /sdcard/stracer/malicious/" + fileName;
                    System.out.println("command is: " + straceCommand);

                    mDevice.shell(straceCommand);

                    //once activity start, do some work on emulator and then close activity
                    Thread.currentThread().sleep(WAIT_AFTER_INSTALL);

                    //pull the straced data to result path
                    String pullCommand = "adb pull /sdcard/stracer/malicious/" + fileName + " " + env.getResultPath() + "dynamic/strace/malicious/" + fileName;
                    System.out.println(pullCommand);
//                mDevice.shell(pullCommand, timeout);
                    Runtime.getRuntime().exec(pullCommand, null, new File(env.getAndroidSDKFilePath() + "platform-tools/"));
                    System.out.println("pulled file");

                    //uninstall the app
                    String forceStopCommand = "adb shell am force-stop " + data.getPackageName();
                    String stopResult = mDevice.shell(forceStopCommand, timeout);
                    System.out.println("Stop Result is: " + stopResult);

                    boolean removeDevice = mDevice.removePackage(data.getAndroidSample().getPathToApk());
                    System.out.println("Removed: " + removeDevice);

                    Thread.currentThread().sleep(WAIT_AFTER_REMOVAL);
                }
            } catch (Exception e) {
                System.out.println("Exception Occurred: " + e);
            }

        }
    }

    private void analyseBenignSamples(EnvironmentVariables env, IChimpDevice mDevice, List<StaticAndroidData> benignSampleDataList) {
        for(StaticAndroidData data : benignSampleDataList) {
            try {
                System.out.println("Starting Now");
                //check if app already installed
//                if()
                String deviceAPKPath = mDevice.shell(String.format("adb shell pm path %s", data.getPackageName()), timeout);
                System.out.println("Checking if package " + data.getPackageName() + "is already installed");

                if (!deviceAPKPath.startsWith("package:")) {
                    //application is not installed
                    mDevice.installPackage(data.getAndroidSample().getPathToApk());
                    System.out.println("Installed Package: " + data.getPackageName());
                }

                //start activity
                String startActivityCommand = "adb shell am start -a android.intent.action.MAIN -n " + data.getPackageName() + "/" + data.getActivityName();
                String result = mDevice.shell(startActivityCommand, timeout);
                System.out.println("starting activity: " + result);

                String processIDCommand = "adb shell ps | grep " + data.getPackageName();
                System.out.println("command is: " + processIDCommand);

                String outputShell = mDevice.shell(processIDCommand, timeout);
                System.out.println("command is: " + outputShell);
                String[] str = outputShell.split("\\s+");
                String processID = str[1];
                System.out.println("Process ID is: " + processID);

                //runStrace command on the package and output data to predefined location on disk
                String fileName = data.getAndroidSample().getName() + ".txt";
                String straceCommand = "adb shell strace -cvf -p " + processID + " -o /sdcard/stracer/benign/" + fileName;
                System.out.println("command is: " + straceCommand);

                mDevice.shell(straceCommand);

                //once activity start, do some work on emulator and then close activity
                Thread.currentThread().sleep(WAIT_AFTER_INSTALL);

                //pull the straced data to result path
                String pullCommand = "adb pull /sdcard/stracer/benign/" + fileName + " " + env.getResultPath() + "dynamic/strace/benign/" + fileName;
                System.out.println(pullCommand);
//                mDevice.shell(pullCommand, timeout);
                Runtime.getRuntime().exec(pullCommand, null, new File(env.getAndroidSDKFilePath()+"platform-tools/"));
                System.out.println("pulled file");

                //uninstall the app
                String forceStopCommand = "adb shell am force-stop " + data.getPackageName();
                String stopResult = mDevice.shell(forceStopCommand, timeout);
                System.out.println("Stop Result is: " + stopResult);


                boolean removeDevice = mDevice.removePackage(data.getAndroidSample().getPathToApk());
                System.out.println("Removed: " + removeDevice);

                Thread.currentThread().sleep(WAIT_AFTER_REMOVAL);
            } catch (Exception e) {
                System.out.println("Exception Occurred: " + e);
            }

        }
    }

    private IChimpDevice initializeTestingEnvironment(EnvironmentVariables env) {
        System.out.println("Starting EMU");

        TreeMap<String, String> options = new TreeMap<String, String>();
        options.put("backend", "adb");
        options.put("adbLocation", env.getAndroidSDKFilePath()+"platform-tools/adb");
        ChimpChat mChimpchat = ChimpChat.getInstance(options);

        final long TIMEOUT = 200000;

        IChimpDevice mDevice = mChimpchat.waitForConnection(TIMEOUT, ".*");
        if ( mDevice == null ) {
            throw new RuntimeException("Couldn't connect.");
        }
        mDevice.wake();

//        mDevice.

//        IChimpDevice device = ab.waitForConnection();
        //Print Device Name
//        System.out.println(device.getProperty("build.model"));

//        device.
        return mDevice;
    }

    public void prepareAndStartEmulator(EnvironmentVariables env) {
        boolean isEmulatorRunning = false;
        final String commandPath = env.getAndroidSDKFilePath();
        String toolsPath = commandPath+"tools/";

        BufferedReader stdInput = null;
        try {
            Process proc = Runtime.getRuntime().exec("adb devices", null, new File(toolsPath));
            stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String buff;

            while ((buff = stdInput.readLine()) != null) {
                if (buff.contains("emulator-5554")) {
                    isEmulatorRunning = true;
                    break;
                }
            }
            if(!isEmulatorRunning){
                proc = Runtime.getRuntime().exec(env.getStartEmulatorCommand(), null, new File(toolsPath));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void createAVD(EnvironmentVariables env) {
        boolean isAVDExists = false;
        final String commandPath = env.getAndroidSDKFilePath();
        String toolsPath = commandPath+"tools/";

        BufferedReader stdInput = null;
        try {
            Process proc = Runtime.getRuntime().exec(env.getCheckAVDExists(), null, new File(toolsPath));
            stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String buff;

            while ((buff = stdInput.readLine()) != null) {
                if(buff.contains("Name: " + env.getAvdName())){
                    isAVDExists = true;
                    break;
                }
            }

            if(!isAVDExists){
                proc = Runtime.getRuntime().exec(env.getCreateAVDCommand(), null, new File(toolsPath));
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
