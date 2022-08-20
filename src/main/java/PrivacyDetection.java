import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.*;
import soot.util.Chain;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.LinkedList;
import java.util.List;

public class PrivacyDetection extends Analysis {
    private List<String> rules = new LinkedList<>();

    public PrivacyDetection() {
        init();
    }

    public void init() {
        System.out.println(System.getProperty("user.dir"));
        String filePath = "./src/main/resources/privacy.txt";

        try {
            FileInputStream fin = new FileInputStream(filePath);
            InputStreamReader reader = new InputStreamReader(fin);
            BufferedReader buffReader = new BufferedReader(reader);
            String str = "";
            while ((str = buffReader.readLine()) != null) {
                rules.add(str);
            }
            buffReader.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public <T> T analysis(String appName, String packageName, Chain<SootClass> classes) {
        for (SootClass cls : classes) {
            if (isExclude(cls.getPackageName())) continue;
            for (SootMethod method : cls.getMethods()) {
                if (method.isPhantom()) continue;
                JimpleBody body = null;
                try {
                    body = (JimpleBody) method.retrieveActiveBody();
                } catch (Exception e) {
//                    e.printStackTrace();
                    continue;
                }

                assert body != null;
                for (Unit unit : body.getUnits()) {
                    unit.apply(new AbstractStmtSwitch() {
                        @Override
                        public void caseAssignStmt(AssignStmt stmt) {
                            String str = stmt.getUseBoxes().toString();
//                            System.out.println(str);
                            check(cls, method, str);

                        }

                        @Override
                        public void caseInvokeStmt(InvokeStmt stmt) {
                            String str = stmt.getUseBoxes().toString();
                            check(cls, method, str);

                        }

                        @Override
                        public void caseReturnStmt(ReturnStmt stmt) {
                            String str = stmt.getUseBoxes().toString();
                            check(cls, method, str);
                        }
                    });
                }
            }
        }
        return null;
    }

    public void check(SootClass cls, SootMethod method, String str) {
        for (String rule : rules) {
            if (str.contains(rule)) {
                System.out.println("检测到隐私api调用");
                System.out.println(str);
                System.out.println(cls.getName() + method.getName());
            }
        }
    }

    public static void main(String[] args) {
        PrivacyDetection p = new PrivacyDetection();
        p.batchAnalysis();
    }
}