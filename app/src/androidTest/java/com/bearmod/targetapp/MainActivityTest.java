package com.bearmod.targetapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.rule.ActivityTestRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.containsString;

@RunWith(AndroidJUnit4.class)
public class MainActivityTest {

    @Rule
    public ActivityTestRule<MainActivity> activityRule = new ActivityTestRule<>(MainActivity.class);

    @Test
    public void testSignatureTextIsDisplayed() {
        // Check that the signature text view is displayed
        onView(withId(R.id.sample_text)).check(matches(isDisplayed()));
        
        // Check that it contains the expected text
        onView(withId(R.id.sample_text)).check(matches(withText(containsString("Signature Status:"))));
    }

    @Test
    public void testNativeButtonIsDisplayed() {
        // Check that the native button is displayed
        onView(withId(R.id.check_native_button)).check(matches(isDisplayed()));
        
        // Check that it has the correct text
        onView(withId(R.id.check_native_button)).check(matches(withText("Check Native Setup")));
    }

    @Test
    public void testNativeButtonClick() {
        // Click the button
        onView(withId(R.id.check_native_button)).perform(click());
        
        // Note: We can't easily test the Toast message in Espresso
        // This test just verifies the button can be clicked without crashing
    }
}
