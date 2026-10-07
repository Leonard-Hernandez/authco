package authco;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import authco.config.TestContainerConfig;

@ActiveProfiles("test")
@SpringBootTest()
@Import(TestContainerConfig.class)
class AuthcoApplicationTests {

	@Test
	void contextLoads() {
	}

}
