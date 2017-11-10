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

import com.h3xstream.findsecbugs.common.ByteCode;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;
import org.apache.bcel.Constants;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ALOAD;
import org.apache.bcel.generic.ASTORE;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.INVOKESPECIAL;
import org.apache.bcel.generic.INVOKEVIRTUAL;
import org.apache.bcel.generic.INVOKEINTERFACE;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import java.util.Iterator;



public class FilePermissionDetector implements Detector { //extends OpcodeStackDetector for sawOpcode().

    private static final String IMPROPER_FILE_PERMISSION = "IMPROPER_FILEUPLOAD";

    private BugReporter bugReporter;

    private static final int TRUE_INT_VALUE = 1;

    public FilePermissionDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();

        Method[] methodList = javaClass.getMethods();

        for (Method m : methodList) {
            try {
                analyzeMethod(m,classContext);
            } catch (CFGBuilderException e) {
            }
        }
    }

    private void analyzeMethod(Method m, ClassContext classContext) throws CFGBuilderException {
        //System.out.println("==="+m.getName()+"===");

        ConstantPoolGen cpg = classContext.getConstantPoolGen();                //String 객체들을 관리 (명령어들이 그렇게 넘어오니까..? 정확히 모르겠ㅇㅓ)
        CFG cfg = classContext.getCFG(m);                                       //Control Flow Graph..음.

        for (Iterator<Location> i = cfg.locationIterator(); i.hasNext(); ) {
            Location loc = i.next();
            //ByteCode.printOpCode(loc.getHandle().getInstruction(), cpg);

            Instruction inst = loc.getHandle().getInstruction();
            if(inst instanceof INVOKESPECIAL) {
                INVOKESPECIAL invoke = (INVOKESPECIAL) inst;
                if ("java.io.File".equals(invoke.getClassName(cpg)) &&
                        "<init>".equals(invoke.getMethodName(cpg))) {

                    // The following call should push the cookie onto the stack
                    Instruction permissionStoreInstruction = loc.getHandle().getNext().getInstruction();
                    if (permissionStoreInstruction instanceof ASTORE) {     //ASTORE가 File 객체 생성된 부분

                        // We will use the position of the object on the stack to track the cookie
                        ASTORE storeInstruction = (ASTORE)permissionStoreInstruction;

                        Location setWritableLocation = getSetWritableLocation(cpg, loc, storeInstruction.getIndex());
                        if (setWritableLocation != null) {

                            JavaClass javaClass = classContext.getJavaClass();

                            bugReporter.reportBug(new BugInstance(this, IMPROPER_FILE_PERMISSION, Priorities.NORMAL_PRIORITY) //
                                    .addClass(javaClass)
                                    .addMethod(javaClass, m)
                                    .addSourceLine(classContext, m, setWritableLocation));
                        }

                        Location setExecutableLocation = getSetExecutableLocation(cpg, loc, storeInstruction.getIndex());
                        if (setExecutableLocation != null) {

                            JavaClass javaClass = classContext.getJavaClass();

                            bugReporter.reportBug(new BugInstance(this, IMPROPER_FILE_PERMISSION, Priorities.NORMAL_PRIORITY) //
                                    .addClass(javaClass)
                                    .addMethod(javaClass, m)
                                    .addSourceLine(classContext, m, setExecutableLocation));
                        }

//                        //Read는 빼기
//                        Location setReadableLocation = getSetReadableLocation(cpg, loc, storeInstruction.getIndex());
//                        if (setReadableLocation != null) {
//
//                            JavaClass javaClass = classContext.getJavaClass();
//
//                            bugReporter.reportBug(new BugInstance(this, IMPROPER_FILE_PERMISSION, Priorities.NORMAL_PRIORITY) //
//                                    .addClass(javaClass)
//                                    .addMethod(javaClass, m)
//                                    .addSourceLine(classContext, m, setReadableLocation));
//                        }



                    }
                }
            }
        }
    }



    /**
     * 반드시 수정하기
     * This method is used to track calls made on a specific object. For instance, this could be used to track if "setHttpOnly(true)"
     * was executed on a specific cookie object.
     *
     * This allows the detector to find interchanged calls like this
     *
     * Cookie cookie1 = new Cookie("f", "foo");     <- This cookie is unsafe
     * Cookie cookie2 = new Cookie("b", "bar");     <- This cookie is safe
     * cookie1.setHttpOnly(false);
     * cookie2.setHttpOnly(true);
     *
     * @param cpg ConstantPoolGen
     * @param startLocation The Location of the cookie initialization call.
     * @param objectStackLocation The index of the cookie on the stack.
     * @param invokeInstruction The instruction we want to detect.s
     * @return The location of the invoke instruction provided for the cookie at a specific index on the stack.
     */

    private Location getPermissionInstructionLocation(ConstantPoolGen cpg, Location startLocation, int objectStackLocation, String invokeInstruction) {
        Location location = startLocation;
        InstructionHandle handle = location.getHandle();

        int loadedStackValue = 0;

        //Loop until we find the setWritable call for this File ?
        while( handle.getNext() != null ){
            handle = handle.getNext();
            Instruction nextInst = handle.getInstruction();

            // We check if the idx of the file method used for this invoke is the same as the one provided
            if( nextInst instanceof ALOAD){
                ALOAD loadInst = (ALOAD)nextInst;
                loadedStackValue = loadInst.getIndex();

            }

            if( nextInst instanceof INVOKEVIRTUAL
                    && loadedStackValue == objectStackLocation){
                INVOKEVIRTUAL invoke = (INVOKEVIRTUAL) nextInst;

                String methodNameWithSignature = invoke.getClassName(cpg) + "." + invoke.getMethodName(cpg);

                if( methodNameWithSignature.equals(invokeInstruction)){
                    Integer val = ByteCode.getConstantInt(handle.getPrev());

                    if(val!=null && val == TRUE_INT_VALUE){
                        return new Location(handle, location.getBasicBlock());
                    }
                }
            }
        }

        return null;
    }


    //TransferTo()가 있는 위치를 반환한다. 없으면 null이겠지. white list methods들을 검증하기 전에 먼저.
    private Location getTransferToInstructionLocation(ConstantPoolGen cpg, Location startLocation, int objectStackLocation, String invokeInstruction){
        Location location = startLocation;
        InstructionHandle handle = location.getHandle();

        int loadedStackValue = 0;

        //Loop until we find the setWritable call for this File ???
        while( handle.getNext() != null ){
            handle = handle.getNext();
            Instruction nextInst = handle.getInstruction();

            // We check if the idx of the file method used for this invoke is the same as the one provided
            if( nextInst instanceof ALOAD){
                ALOAD loadInst = (ALOAD)nextInst;
                loadedStackValue = loadInst.getIndex();
            }

            if( nextInst instanceof INVOKEINTERFACE
                    && loadedStackValue == objectStackLocation){
                INVOKEINTERFACE invoke = (INVOKEINTERFACE) nextInst;
                String methodNameWithSignature = invoke.getClassName(cpg) + "." + invoke.getMethodName(cpg);

                if( methodNameWithSignature.equals(invokeInstruction)){
                    return new Location(handle, location.getBasicBlock());
                }
            }
        }

        return null;
    }


    // setWritable()
    private Location getSetWritableLocation(ConstantPoolGen cpg, Location startLocation, int stackLocation) {
        if(getTransferToInstructionLocation(cpg, startLocation, stackLocation, "org.springframework.web.multipart.MultipartFile.transferTo") != null){
            return getPermissionInstructionLocation(cpg, startLocation, stackLocation, "java.io.File.setWritable");
        }
        else{
            return null;
        }
    }


    // setExecutable()
    private Location getSetExecutableLocation(ConstantPoolGen cpg, Location startLocation, int stackLocation) {
        if(getTransferToInstructionLocation(cpg, startLocation, stackLocation, "org.springframework.web.multipart.MultipartFile.transferTo") != null){
            return getPermissionInstructionLocation(cpg, startLocation, stackLocation, "java.io.File.setExecutable");
        }
        else{
            return null;
        }
    }

//    // setReadable()
//    private Location getSetReadableLocation(ConstantPoolGen cpg, Location startLocation, int stackLocation) {
//        if(getTransferToInstructionLocation(cpg, startLocation, stackLocation, "org.springframework.web.multipart.MultipartFile.transferTo") != null){
//            return getPermissionInstructionLocation(cpg, startLocation, stackLocation, "java.io.File.setReadable");
//        }
//        else{
//            return null;
//        }
//    }


    @Override
    public void report() {

    }

}
