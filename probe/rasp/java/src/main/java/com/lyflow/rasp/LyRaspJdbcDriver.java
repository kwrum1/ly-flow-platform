package com.lyflow.rasp;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

final class LyRaspJdbcDriver implements Driver {
    static final String PREFIX = "jdbc:lyrasp:";
    private static volatile boolean prefixInstalled;

    static synchronized void install() throws SQLException {
        if (!prefixInstalled) {
            DriverManager.registerDriver(new LyRaspJdbcDriver());
            prefixInstalled = true;
        }
        List<Driver> drivers = new ArrayList<Driver>();
        Enumeration<Driver> current = DriverManager.getDrivers();
        while (current.hasMoreElements()) {
            Driver driver = current.nextElement();
            if (!(driver instanceof LyRaspJdbcDriver) && !(driver instanceof TransparentDriver)) {
                drivers.add(driver);
            }
        }
        for (Driver driver : drivers) {
            DriverManager.deregisterDriver(driver);
            DriverManager.registerDriver(new TransparentDriver(driver));
        }
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) return null;
        String delegateURL = url.substring(PREFIX.length());
        Driver driver = findDelegate(delegateURL);
        Connection connection = driver.connect(delegateURL, info);
        if (connection == null) return null;
        return proxyConnection(connection, delegateURL);
    }

    @Override
    public boolean acceptsURL(String url) {
        return url != null && url.startsWith(PREFIX);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        return findDelegate(url.substring(PREFIX.length())).getPropertyInfo(url.substring(PREFIX.length()), info);
    }

    @Override public int getMajorVersion() { return 1; }
    @Override public int getMinorVersion() { return 0; }
    @Override public boolean jdbcCompliant() { return false; }
    @Override public Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException(); }

    private Driver findDelegate(String delegateURL) throws SQLException {
        Enumeration<Driver> drivers = DriverManager.getDrivers();
        while (drivers.hasMoreElements()) {
            Driver driver = drivers.nextElement();
            if (driver == this || driver instanceof LyRaspJdbcDriver) continue;
            if (driver.acceptsURL(delegateURL)) return driver;
        }
        throw new SQLException("No delegate JDBC driver accepts " + delegateURL);
    }

    private static final class TransparentDriver implements Driver {
        private final Driver delegate;

        TransparentDriver(Driver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            Connection connection = delegate.connect(url, info);
            if (connection == null) return null;
            return proxyConnection(connection, url);
        }

        @Override
        public boolean acceptsURL(String url) throws SQLException {
            return delegate.acceptsURL(url);
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
            return delegate.getPropertyInfo(url, info);
        }

        @Override public int getMajorVersion() { return delegate.getMajorVersion(); }
        @Override public int getMinorVersion() { return delegate.getMinorVersion(); }
        @Override public boolean jdbcCompliant() { return delegate.jdbcCompliant(); }
        @Override public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            try {
                return delegate.getParentLogger();
            } catch (AbstractMethodError e) {
                throw new SQLFeatureNotSupportedException();
            }
        }
    }

    private static Connection proxyConnection(Connection connection, String url) {
        return (Connection) Proxy.newProxyInstance(connection.getClass().getClassLoader(), new Class<?>[]{Connection.class}, new ConnectionHandler(connection, url));
    }

    private static final class ConnectionHandler implements InvocationHandler {
        private final Connection delegate;
        private final String url;

        ConnectionHandler(Connection delegate, String url) {
            this.delegate = delegate;
            this.url = url;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();
            if (("prepareStatement".equals(name) || "prepareCall".equals(name)) && args != null && args.length > 0 && args[0] instanceof String) {
                String sql = (String) args[0];
                emitSql(sql, "Connection." + name, url);
                Object result = method.invoke(delegate, args);
                if (result instanceof PreparedStatement) return proxyPrepared((PreparedStatement) result, sql, url);
                return result;
            }
            if ("createStatement".equals(name)) {
                Object result = method.invoke(delegate, args);
                if (result instanceof Statement) return proxyStatement((Statement) result, url);
                return result;
            }
            return method.invoke(delegate, args);
        }
    }

    private static Statement proxyStatement(Statement statement, String url) {
        return (Statement) Proxy.newProxyInstance(statement.getClass().getClassLoader(), new Class<?>[]{Statement.class}, new StatementHandler(statement, url));
    }

    private static PreparedStatement proxyPrepared(PreparedStatement statement, String sql, String url) {
        return (PreparedStatement) Proxy.newProxyInstance(statement.getClass().getClassLoader(), new Class<?>[]{PreparedStatement.class}, new PreparedHandler(statement, sql, url));
    }

    private static final class StatementHandler implements InvocationHandler {
        private final Statement delegate;
        private final String url;

        StatementHandler(Statement delegate, String url) {
            this.delegate = delegate;
            this.url = url;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (args != null && args.length > 0 && args[0] instanceof String && method.getName().startsWith("execute")) {
                emitSql((String) args[0], "Statement." + method.getName(), url);
            }
            return method.invoke(delegate, args);
        }
    }

    private static final class PreparedHandler implements InvocationHandler {
        private final PreparedStatement delegate;
        private final String sql;
        private final String url;

        PreparedHandler(PreparedStatement delegate, String sql, String url) {
            this.delegate = delegate;
            this.sql = sql;
            this.url = url;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getName().startsWith("execute")) emitSql(sql, "PreparedStatement." + method.getName(), url);
            return method.invoke(delegate, args);
        }
    }

    private static void emitSql(String sql, String sink, String url) {
        if (LyRaspAgent.suspiciousSql(sql)) {
            LyRaspAgent.emit("rasp.sql", "java", "sql", sql, sink + " " + url);
        }
    }
}
