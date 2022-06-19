package com.firebaseAuthenticators

import android.annotation.SuppressLint
import android.app.Activity
import android.util.Log
import android.widget.EditText
import com.google.firebase.FirebaseException
import com.google.firebase.FirebaseTooManyRequestsException
import com.google.firebase.auth.*
import java.util.concurrent.TimeUnit

@SuppressLint("StaticFieldLeak")
object FirebaseOtpAuthenticator {

    val TAG = this::class.simpleName.toString()

    private val auth: FirebaseAuth by lazy {
        FirebaseAuth.getInstance()
    }
    private lateinit var otpActivity: Activity
    private var otpEditText: EditText? = null
    private var shouldAutomaticVerify: Boolean = false
    private lateinit var countryCode: String
    private lateinit var mobileNumber: String
    private lateinit var listener: OtpSendListener
    private var storedVerificationId: String? = null
    private var storedToken: PhoneAuthProvider.ForceResendingToken? = null

    fun sendOtpToNumber(activity: Activity, cCode: String, phoneNumber: String, otpEditText: EditText? = null, automaticVerify: Boolean = false, otpSendListener: OtpSendListener) {
        otpActivity = activity
        FirebaseOtpAuthenticator.otpEditText = otpEditText
        shouldAutomaticVerify = automaticVerify
        listener = otpSendListener
        countryCode = cCode
        mobileNumber = phoneNumber
        val callbacks = object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
            override fun onVerificationCompleted(credential: PhoneAuthCredential) {
                val code = credential.smsCode
                code?.let { otp ->
                    otpEditText?.let { et ->
                        et.setText(otp)
                        if (shouldAutomaticVerify)
                            signInWithPhoneAuthCredential(credential)
                    }
                }
            }

            override fun onVerificationFailed(exception: FirebaseException) {
                Log.d(TAG, "$TAG verification failed: $exception")
                when (exception) {
                    is FirebaseAuthInvalidCredentialsException -> listener.onOtpSentError(SendOtpError.InvalidPhoneNumber)
                    is FirebaseTooManyRequestsException -> listener.onOtpSentError(SendOtpError.TooManyRequestSent)
                    else -> listener.onOtpSentError(SendOtpError.SomeOtherError(exception))
                }
            }

            override fun onCodeSent(verificationId: String, token: PhoneAuthProvider.ForceResendingToken) {
                storedVerificationId = verificationId
                storedToken = token
                listener.onOtpSent()
            }
        }

        val options = PhoneAuthOptions.newBuilder(auth)
            .setPhoneNumber(countryCode + mobileNumber).also { Log.d(TAG, "sendOtpToNumber: $countryCode$mobileNumber") }
            .setTimeout(60L, TimeUnit.SECONDS)
            .setActivity(otpActivity)
            .setCallbacks(callbacks).apply {
                if (storedToken != null)
                    setForceResendingToken(storedToken!!)
            }
            .build()
        PhoneAuthProvider.verifyPhoneNumber(options)
    }

    fun resendOtp() {
        sendOtpToNumber(otpActivity, countryCode, mobileNumber, otpEditText, shouldAutomaticVerify, listener)
    }

    fun verifyOtp(code: String) {
        if (storedVerificationId == null)
            return
        val credential = PhoneAuthProvider.getCredential(storedVerificationId!!, code)
        signInWithPhoneAuthCredential(credential)
    }

    private fun signInWithPhoneAuthCredential(credential: PhoneAuthCredential) {
        auth.signInWithCredential(credential).addOnCompleteListener { authTask ->
            if (authTask.isSuccessful) {
                Log.d(TAG, "$TAG signInWithCredential:success")
                listener.onVerificationSuccessful()
            } else {
                when (authTask.exception) {
                    is FirebaseAuthInvalidCredentialsException -> listener.onVerificationFailed(VerifyOtpError.InValidOtp)
                    else -> listener.onVerificationFailed(VerifyOtpError.SomeOtherError(authTask.exception!!))
                }
            }
        }
    }


    interface OtpSendListener {
        fun onOtpSent()
        fun onOtpSentError(error: SendOtpError)
        fun onVerificationSuccessful()
        fun onVerificationFailed(error: VerifyOtpError)
    }

    sealed class SendOtpError {
        object InvalidPhoneNumber : SendOtpError()
        object TooManyRequestSent : SendOtpError()
        data class SomeOtherError(val error: java.lang.Exception) : SendOtpError()
    }

    sealed class VerifyOtpError {
        object InValidOtp : VerifyOtpError()
        data class SomeOtherError(val error: java.lang.Exception) : VerifyOtpError()
    }
}