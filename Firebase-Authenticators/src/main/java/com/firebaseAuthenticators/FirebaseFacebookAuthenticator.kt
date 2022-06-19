package com.firebaseAuthenticators

import android.app.Activity
import android.content.Intent
import android.util.Log
import com.facebook.AccessToken
import com.facebook.CallbackManager
import com.facebook.FacebookSdk
import com.facebook.LoginStatusCallback
import com.facebook.appevents.AppEventsLogger
import com.facebook.login.LoginManager
import com.google.firebase.auth.AuthResult
import com.google.firebase.auth.FacebookAuthProvider
import com.google.firebase.auth.FirebaseAuth

object FirebaseFacebookAuthenticator {

    val TAG = this::class.java.simpleName.toString()
    const val RC_FACEBOOK_SIGN_IN = 151

    private val callbackManager by lazy {
        CallbackManager.Factory.create()
    }
    private val auth by lazy {
        FirebaseAuth.getInstance()
    }
    private var callbacks: FacebookLoginCallbacks? = null

    /**
     * Use following url to check all available permissions
     * https://developers.facebook.com/docs/permissions/reference/
     */
    fun startLogin(
        activity: Activity, callbacks: FacebookLoginCallbacks,
        permissionList: List<String> = listOf(
            "email",
            "public_profile"
        ),
    ) {
        FacebookSdk.sdkInitialize(activity.application.applicationContext)
        AppEventsLogger.activateApp(activity.application)
        FirebaseFacebookAuthenticator.callbacks = callbacks
        val instance = LoginManager.getInstance()
        instance.logInWithReadPermissions(activity, permissionList);

        instance.retrieveLoginStatus(activity, object : LoginStatusCallback {
            override fun onCompleted(accessToken: AccessToken) {
                Log.d(TAG, "onSuccess: $accessToken")
                handleFacebookAccessToken(activity, accessToken)
            }

            override fun onError(exception: Exception) {
                Log.d(TAG, "onError: $exception")
                FirebaseFacebookAuthenticator.callbacks?.onError(exception)
            }

            override fun onFailure() {
                Log.d(TAG, "onFailure: Called when an access token could not be retrieved.")
                callbacks.onError(java.lang.Exception("Developer Error"))
            }

        })
    }

    /**
     * It will initiate the firebase login procedure with facebook
     * and return appropriate callback
     */
    private fun handleFacebookAccessToken(
        activity: Activity, token: AccessToken,
    ) {
        val credential = FacebookAuthProvider.getCredential(token.token)
        auth.signInWithCredential(credential)
            .addOnCompleteListener(activity) { task ->
                if (task.isSuccessful) {
                    callbacks?.onSuccess(task.result)
                } else {
                    Log.e(TAG, "$TAG facebook auth error: ${task.exception}")
                    callbacks?.onError(task.exception!!)
                }
            }
    }

    /**
     * Use this function to handle activity result
     */
    fun registerActivityResultCallback(requestCode: Int, resultCode: Int, data: Intent?) {
        callbackManager.onActivityResult(requestCode, resultCode, data)
    }

    interface FacebookLoginCallbacks {
        fun onCancel()
        fun onError(error: Exception)
        fun onSuccess(result: AuthResult)
    }
}