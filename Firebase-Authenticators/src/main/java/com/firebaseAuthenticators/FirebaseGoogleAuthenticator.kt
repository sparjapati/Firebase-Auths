package com.firebaseAuthenticators

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.res.Resources.NotFoundException
import android.util.Log
import com.google.android.gms.auth.api.Auth
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider

@SuppressLint("StaticFieldLeak")
object FirebaseGoogleAuthenticator {

    private val TAG = this::class.simpleName.toString()
    const val RC_GOOGLE_SIGN_IN = 191

    private val auth by lazy {
        FirebaseAuth.getInstance()
    }
    private var mGoogleSignInClient: GoogleSignInClient? = null
    private var listener: GoogleLoginListener? = null

    fun signIn(activity: Activity, webClientId: Int, googleLoginListener: GoogleLoginListener, requestForEmail: Boolean = true, requestForProfileInfo: Boolean = true) {
        listener = googleLoginListener
        val defaultWebClientId = try {
            activity.resources.getString(webClientId)
        } catch (e: NotFoundException) {
            listener!!.onGoogleLoginError(e)
            return
        }
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(defaultWebClientId).apply {
                if (requestForEmail)
                    requestEmail()
                if (requestForProfileInfo)
                    requestProfile()
            }
            .build()
        mGoogleSignInClient = GoogleSignIn.getClient(activity, gso)
        val intent = mGoogleSignInClient!!.signInIntent
        activity.startActivityForResult(intent, RC_GOOGLE_SIGN_IN)
    }

    interface GoogleLoginListener {
        // something went wrong while login with google
        fun onGoogleLoginError(error: Exception)

        // something went wrong while authenticating with firebase
        fun onFirebaseAuthenticationError(error: Exception)

        fun onLoginSuccessfully(currentUser: FirebaseUser)
    }

    fun handleGoogleSignInResult(data: Intent) {
        val result = Auth.GoogleSignInApi.getSignInResultFromIntent(data)
        mGoogleSignInClient?.signOut()
        if (result != null) {
            if (result.isSuccess) {
                val credential = GoogleAuthProvider.getCredential(result.signInAccount!!.idToken, null)
                auth.signInWithCredential(credential).addOnCompleteListener { firebaseAuthTask ->
                    if (firebaseAuthTask.isSuccessful) {
                        listener?.onLoginSuccessfully(auth.currentUser!!)
                    } else {
                        Log.e(TAG, "$TAG firebaseAuthenticationError: ${firebaseAuthTask.exception}")
                        listener?.onFirebaseAuthenticationError(firebaseAuthTask.exception!!)
                    }


                }
            } else {
                listener?.onGoogleLoginError(java.lang.Exception("Something went wrong"))
            }
        }
    }


}