package com.lyflow.rasp;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.security.Permission;

@SuppressWarnings("removal")
final class LyRaspSecurityManager extends SecurityManager {
    private final SecurityManager delegate;

    LyRaspSecurityManager(SecurityManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void checkExec(String cmd) {
        if (LyRaspAgent.isEmitting()) {
            if (delegate != null) delegate.checkExec(cmd);
            return;
        }
        LyRaspAgent.emit("rasp.exec", "java", "exec", cmd, "SecurityManager.checkExec");
        if (delegate != null) delegate.checkExec(cmd);
    }

    @Override
    public void checkRead(String file) {
        if (LyRaspAgent.isEmitting()) {
            if (delegate != null) delegate.checkRead(file);
            return;
        }
        if (LyRaspAgent.sensitivePath(file)) {
            LyRaspAgent.emit("rasp.file", "java", "file.read", file, "SecurityManager.checkRead");
        }
        if (delegate != null) delegate.checkRead(file);
    }

    @Override
    public void checkWrite(String file) {
        if (LyRaspAgent.isEmitting()) {
            if (delegate != null) delegate.checkWrite(file);
            return;
        }
        if (LyRaspAgent.sensitivePath(file)) {
            LyRaspAgent.emit("rasp.file", "java", "file.write", file, "SecurityManager.checkWrite");
        }
        if (delegate != null) delegate.checkWrite(file);
    }

    @Override
    public void checkConnect(String host, int port) {
        if (LyRaspAgent.isEmitting()) {
            if (delegate != null) delegate.checkConnect(host, port);
            return;
        }
        String target = host + ":" + port;
        if (LyRaspAgent.sensitiveUrl(target)) {
            LyRaspAgent.emit("rasp.ssrf", "java", "ssrf", target, "SecurityManager.checkConnect");
        }
        if (delegate != null) delegate.checkConnect(host, port);
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        checkConnect(host, port);
    }

    @Override public void checkPermission(Permission perm) { if (delegate != null) delegate.checkPermission(perm); }
    @Override public void checkPermission(Permission perm, Object context) { if (delegate != null) delegate.checkPermission(perm, context); }
    @Override public void checkCreateClassLoader() { if (delegate != null) delegate.checkCreateClassLoader(); }
    @Override public void checkAccess(Thread t) { if (delegate != null) delegate.checkAccess(t); }
    @Override public void checkAccess(ThreadGroup g) { if (delegate != null) delegate.checkAccess(g); }
    @Override public void checkExit(int status) { if (delegate != null) delegate.checkExit(status); }
    @Override public void checkLink(String lib) { if (delegate != null) delegate.checkLink(lib); }
    @Override public void checkRead(FileDescriptor fd) { if (delegate != null) delegate.checkRead(fd); }
    @Override public void checkRead(String file, Object context) { checkRead(file); }
    @Override public void checkWrite(FileDescriptor fd) { if (delegate != null) delegate.checkWrite(fd); }
    @Override public void checkDelete(String file) { if (delegate != null) delegate.checkDelete(file); }
    @Override public void checkListen(int port) { if (delegate != null) delegate.checkListen(port); }
    @Override public void checkAccept(String host, int port) { if (delegate != null) delegate.checkAccept(host, port); }
    @Override public void checkMulticast(InetAddress maddr) { if (delegate != null) delegate.checkMulticast(maddr); }
    @Override public void checkPropertiesAccess() { if (delegate != null) delegate.checkPropertiesAccess(); }
    @Override public void checkPropertyAccess(String key) { if (delegate != null) delegate.checkPropertyAccess(key); }
    @Override public void checkPrintJobAccess() { if (delegate != null) delegate.checkPrintJobAccess(); }
    @Override public void checkPackageAccess(String pkg) { if (delegate != null) delegate.checkPackageAccess(pkg); }
    @Override public void checkPackageDefinition(String pkg) { if (delegate != null) delegate.checkPackageDefinition(pkg); }
    @Override public void checkSetFactory() { if (delegate != null) delegate.checkSetFactory(); }
    @Override public void checkSecurityAccess(String target) { if (delegate != null) delegate.checkSecurityAccess(target); }
}
