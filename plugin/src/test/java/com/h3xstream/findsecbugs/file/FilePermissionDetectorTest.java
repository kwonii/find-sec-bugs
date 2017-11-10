/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.file;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class FilePermissionDetectorTest extends BaseDetectorTest {

    @Test
    public void detectTaintedFilename() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/FilePermission")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);


        for(Integer line : Arrays.asList(21,23)) {
            verify(reporter).doReportBug(
                    bugDefinition()
                            .bugType("IMPROPER_FILEUPLOAD")
                            .inClass("FilePermission").inMethod("doTest").atLine(line)
                            .build()
            );
        }



    }


//
//    @Test
//    public void detectSecureFlagCookieBasic() throws Exception {
//        //Locate test code
//        String[] files = {
//                getClassFilePath("testcode/FilePermission")
//        };
//
//        //Run the analysis
//        EasyBugReporter reporter = spy(new SecurityReporter());
//        analyze(files, reporter);
//
//        for (String method : Arrays.asList("unsafeFile1")) {
//            verify(reporter).doReportBug(
//                    bugDefinition()
//                            .bugType("IMPROPER_FILEUPLOAD")
//                            .inClass("FilePermission").inMethod(method)
//                            .build()
//            );
//        }
//    }

    //    @Test
//    public void avoidSecureFlagBasicFalsePositive() throws Exception {
//        //Locate test code
//        String[] files = {
//                getClassFilePath("testcode/cookie/InsecureCookieSamples")
//        };
//
//        //Run the analysis
//        EasyBugReporter reporter = spy(new SecurityReporter());
//        analyze(files, reporter);
//
//        for (String method : Arrays.asList("safeCookie1", "safeCookie2")) {
//            verify(reporter,never()).doReportBug(
//                    bugDefinition()
//                            .bugType("INSECURE_COOKIE")
//                            .inClass("InsecureCookieSamples").inMethod(method)
//                            .build()
//            );
//        }
//
//        // Advanced checks when multiple cookies are set
//        verify(reporter, times(4)).doReportBug(
//                bugDefinition()
//                        .bugType("INSECURE_COOKIE")
//                        .inClass("InsecureCookieSamples").inMethod("multipleCookies")
//                        .build()
//        );
//    }
}
