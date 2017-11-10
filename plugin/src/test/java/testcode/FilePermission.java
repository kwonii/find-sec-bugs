package testcode;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

public class FilePermission {


    public void doTest(MultipartFile mFile) throws IOException {
        File uFile = new File("./.");

        uFile.setExecutable(true, true);
        uFile.setReadable(true, true);
        uFile.setWritable(true, true);

        mFile.transferTo(uFile);
    }

}
