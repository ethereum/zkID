package com.openac.app;

import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;
import dev.flutter.plugins.integration_test.FlutterTestRunner;
import org.junit.Rule;
import org.junit.runner.RunWith;

@RunWith(FlutterTestRunner.class)
public class MainActivityTest {
  // Screen-off moves the app off the top-app cpuset and resets thread affinity,
  // so keep the device awake for the whole run. Static init: FlutterTestRunner
  // may not run @BeforeClass.
  static {
    try (ParcelFileDescriptor pfd = InstrumentationRegistry.getInstrumentation()
        .getUiAutomation().executeShellCommand("svc power stayon true")) {
    } catch (Exception e) {
      // Best effort: a device that refuses still runs the benchmark.
      Log.w("OPENAC", "svc power stayon failed", e);
    }
  }

  @Rule
  public ActivityTestRule<MainActivity> rule = new ActivityTestRule<>(MainActivity.class, true, false);
}
