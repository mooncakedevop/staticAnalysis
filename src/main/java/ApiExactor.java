import org.apache.commons.io.FileUtils;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiExactor {
    //设置android的jar包目录
    public final static String androidPlatformPath = "/Users/mooncake/Library/Android/sdk/platforms";
    //设置要分析的APK文件

    //匹配restful url

    public static String urlReg = "(?:https?:/)?/[a-zA-Z][a-zA-Z]+(/[a-zA-Z][a-zA-Z]+)+";
    public static Pattern pattern = Pattern.compile(urlReg, Pattern.CASE_INSENSITIVE);
    // 要排除的包
    static List<String> excludePackagesList = new ArrayList<>();
    public static String excludeReg = ".*(activity|ui|lang).*";
    public static Pattern excludePattern = Pattern.compile(excludeReg);

    static {
        excludePackagesList.add("java.");
        excludePackagesList.add("android.");
        excludePackagesList.add("javax.");
        excludePackagesList.add("android.support.");
        excludePackagesList.add("sun.");
        excludePackagesList.add("com.google.");
        excludePackagesList.add("com.alibaba.fastjson.");
        excludePackagesList.add("com.alibaba.android.");
    }

    static {
        //忽略无法解析的类
        Options.v().set_allow_phantom_refs(true);
//        Options.v().set_validate(true);
        //解析apk
        Options.v().ignore_resolution_errors();
        Options.v().set_src_prec(Options.src_prec_apk);
        //设置android的jar包目录
        Options.v().set_android_jars(androidPlatformPath);
        //设置要分析的APK文件

        //处理多个dex文件
        Options.v().set_process_multiple_dex(true);
        Options.v().set_whole_program(true);


//        Options.v().set_output_dir("D:\\code");
        //设置逆向得到的源码格式
        Options.v().set_output_format(Options.output_format_jimple);
        //强制覆盖
        Options.v().set_force_overwrite(true);
        //load dex中的class

    }


    public static void extractApi(String appDirPath) throws XmlPullParserException, IOException {
        System.out.println(Scene.v().getAndroidAPIVersion());
        ProcessManifest processManifest = new ProcessManifest(appDirPath);
        String value = (String) processManifest.getManifest().getAttribute("package").getValue() + ".*";
        Pattern pkgPattern = Pattern.compile(value);
        System.out.println(Scene.v().getClasses().size());

        for (SootClass sootClass : Scene.v().getClasses()) {
            //遍历类中的每一个方法
//            if (!pkgPattern.matcher(sootClass.getName()).matches()) {
//                continue;
//            }
            for (SootMethod sootMethod : sootClass.getMethods()) {
                {
                    if (isExcludeClass(sootClass)) {
                        continue;
                    }
                    if (!sootMethod.hasActiveBody()) {
                        continue;
                    }
                    //遍历方法中的每一行,检查url
                    List<ValueBox> useBoxes = sootMethod.getActiveBody().getUseBoxes();
                    for (ValueBox valueBox : useBoxes) {
                        String content = valueBox.toString();

                        Matcher matcher = pattern.matcher(content);
                        if (!matcher.find()) continue;
                        if (excludePattern.matcher(matcher.group()).matches()) continue;
                        System.out.println(matcher.group());

//                        writeToFile(content);
//                        writeToFile(matcher.group() + "---" + sootClass.getName() + "---" + sootMethod.getSignature());
//                        writeToFile("***********************************************************");
                    }
                }
            }


        }

    }

    public static void writeToFile(String content) {
        try {
            FileUtils.writeStringToFile(new File("/Users/mooncake/IdeaProjects/staticAnalysis/api.txt"), content + "\r\n", "utf-8", true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    protected static boolean isExcludeClass(SootClass sootClass) {
        if (sootClass.isPhantom()) {
            return true;
        }

        String packageName = sootClass.getPackageName();
        for (String exclude : excludePackagesList) {
            if (packageName.startsWith(exclude)) {
                return true;
            }
        }

        return false;
    }

    public static List<String> allFile(String path) {
        List<String> fileList = new ArrayList<>();
        File file = new File(path);
        File[] files = file.listFiles();
        for (File f : files) {
            if (f.isDirectory()) {
                allFile(f.getAbsolutePath());
            } else {
                fileList.add(f.getAbsolutePath());
            }
        }
        return fileList;
    }


    public static void main(String[] args) throws XmlPullParserException, IOException {
        for (String file : allFile("/Users/mooncake/car")) {
            if(!file.contains(".apk")) continue;
            Options.v().set_process_dir(Collections.singletonList(file));
            try {
                Scene.v().loadNecessaryClasses();
                PackManager.v().runPacks();
                extractApi(file);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println(file);
            }
            //开始解析


        }

    }


}

