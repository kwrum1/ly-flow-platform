package com.lyflow.rasp.java.instrument;

import com.lyflow.rasp.java.config.InstrumentationScope;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

final class ApplicationTransformerTest {
    private final ApplicationTransformer transformer =
            new ApplicationTransformer(InstrumentationScope.fixtureOnly());

    @Test
    void allowlistedContractClassIsInstrumented() throws IOException {
        // Given
        byte[] original = classBytes("/com/lyflow/rasp/fixture/FixtureMain.class");

        // When
        byte[] transformed = transformer.transform(
                getClass().getClassLoader(),
                "com/lyflow/rasp/fixture/FixtureMain",
                null,
                null,
                original);

        // Then
        assertNotNull(transformed);
    }

    @Test
    void allowlistedClassWithoutContractsIsUntouched() throws IOException {
        // Given
        byte[] original = classBytes("/com/lyflow/rasp/fixture/NoContract.class");

        // When
        byte[] transformed = transformer.transform(
                getClass().getClassLoader(),
                "com/lyflow/rasp/fixture/NoContract",
                null,
                null,
                original);

        // Then
        assertNull(transformed);
    }

    @Test
    void unsupportedPackageIsUntouched() throws IOException {
        // Given
        byte[] original = classBytes("/com/lyflow/rasp/fixture/FixtureMain.class");

        // When
        byte[] transformed = transformer.transform(
                getClass().getClassLoader(), "java/lang/String", null, null, original);

        // Then
        assertNull(transformed);
        assertArrayEquals(original, original.clone());
    }

    @Test
    void malformedBytecodeFallsBackWithoutTransform() {
        // Given
        byte[] unsupported = new byte[]{0, 1, 2, 3};

        // When
        byte[] transformed = transformer.transform(
                getClass().getClassLoader(),
                "com/lyflow/rasp/fixture/Unsupported",
                null,
                null,
                unsupported);

        // Then
        assertNull(transformed);
    }

    private static byte[] classBytes(String resource) throws IOException {
        try (InputStream input = ApplicationTransformerTest.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("missing fixture class " + resource);
            }
            return input.readAllBytes();
        }
    }
}
