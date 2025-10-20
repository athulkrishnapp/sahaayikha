// In app/static/firebase-messaging-sw.js

// Scripts for Firebase
importScripts("https://www.gstatic.com/firebasejs/9.6.1/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/9.6.1/firebase-messaging-compat.js");

// TODO: Add your web app's Firebase configuration here
  const firebaseConfig = {
    apiKey: "AIzaSyD5X8PdNtRvCW4LGmL4wtbKyJta4MqHTM0",
    authDomain: "sahaayikha.firebaseapp.com",
    projectId: "sahaayikha",
    storageBucket: "sahaayikha.firebasestorage.app",
    messagingSenderId: "1058228709545",
    appId: "1:1058228709545:web:41532a794a0868aebf61b8",
    measurementId: "G-XMW111NJHK"
  };

// Initialize the Firebase app in the service worker
firebase.initializeApp(firebaseConfig);

// Retrieve an instance of Firebase Messaging
const messaging = firebase.messaging();

// Background message handler (optional)
messaging.onBackgroundMessage((payload) => {
  console.log('[firebase-messaging-sw.js] Received background message ', payload);
  
  const notificationTitle = payload.notification.title;
  const notificationOptions = {
    body: payload.notification.body,
    icon: '/static/images/logo.png' // Optional: Add a path to your app's logo
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});