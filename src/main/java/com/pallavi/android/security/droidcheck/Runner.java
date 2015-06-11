package com.pallavi.android.security.droidcheck;

import com.pallavi.android.security.droidcheck.analyser.DynamicAnalyser;
import com.pallavi.android.security.droidcheck.analyser.StaticAnalyser;
import com.pallavi.android.security.droidcheck.domain.StaticAndroidData;
import com.pallavi.android.security.droidcheck.utils.EnvironmentVariables;

import java.util.List;
import java.util.Map;

/**
 * INPUT:
 * APK_FILE_PATH: should be the path where directories benign and malicious are created, which in turn contain directory apks.
 * apks directory will contain all the sample apks.
 * <p/>
 * BASE_PATH: The path where android sdk is stored.
 * VERSION: version of the build tools to use, use any of the ones installed on the system.
 * SDK_FILE_PATH: represents the full path of the 'aapt' tool.
 * <p/>
 * RESULT_PATH: The path to output Results of analysis.
 * <p/>
 * Created by ankit on 15/05/15.
 */
public class Runner {

    public static void main(String[] args) {
        EnvironmentVariables env = EnvironmentVariables.prepareEnvironment();

        DynamicAnalyser dynamicAnalyser = new DynamicAnalyser();
        dynamicAnalyser.createAVD(env);
        dynamicAnalyser.prepareAndStartEmulator(env);

        try {
            System.out.println("Making Thread Sleep, till emulator is up");
            Thread.currentThread().sleep(1000*1*1);
        } catch (InterruptedException e) {
            System.out.println("Thread Was Interrupted");
        }

        Map<String, List<StaticAndroidData>> staticAnalysisMap = new StaticAnalyser().analyse(env);

        dynamicAnalyser.analyse(env, staticAnalysisMap);
    }
}
