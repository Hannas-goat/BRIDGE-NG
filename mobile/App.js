import { useCallback, useEffect, useRef, useState } from 'react';
import { ActivityIndicator, BackHandler, Linking, Pressable, SafeAreaView, StatusBar, StyleSheet, Text, View } from 'react-native';
import { WebView } from 'react-native-webview';

const SITE_URL = 'https://bridge-ng.onrender.com';

export default function App() {
  const webViewRef = useRef(null);
  const [canGoBack, setCanGoBack] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [webviewKey, setWebviewKey] = useState(0);

  // Keep navigation inside the WebView only for the real site — anything else (mailto:,
  // external job application links, social links) opens in the device's own browser/app
  // instead of trapping the user inside the wrapper.
  const handleShouldStartLoad = useCallback((request) => {
    if (request.url.startsWith(SITE_URL) || request.url === 'about:blank') return true;
    Linking.openURL(request.url).catch(() => {});
    return false;
  }, []);

  useEffect(() => {
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      if (canGoBack && webViewRef.current) {
        webViewRef.current.goBack();
        return true;
      }
      return false;
    });
    return () => sub.remove();
  }, [canGoBack]);

  const retry = () => {
    setLoadError(false);
    setWebviewKey((k) => k + 1);
  };

  return (
    <SafeAreaView style={styles.safe}>
      <StatusBar barStyle="dark-content" backgroundColor="#FBF6EA" />
      {loadError ? (
        <View style={styles.center}>
          <Text style={styles.errorText}>Couldn't load Bridge NG. Check your connection and try again.</Text>
          <Pressable style={styles.retryBtn} onPress={retry}>
            <Text style={styles.retryText}>Retry</Text>
          </Pressable>
        </View>
      ) : (
        <WebView
          key={webviewKey}
          ref={webViewRef}
          source={{ uri: SITE_URL }}
          style={styles.webview}
          onNavigationStateChange={(navState) => setCanGoBack(navState.canGoBack)}
          onShouldStartLoadWithRequest={handleShouldStartLoad}
          onError={() => setLoadError(true)}
          onHttpError={(e) => { if (e.nativeEvent.statusCode >= 500) setLoadError(true); }}
          startInLoadingState
          renderLoading={() => (
            <View style={styles.loadingOverlay}>
              <ActivityIndicator size="large" color="#1B2A4A" />
            </View>
          )}
          allowsBackForwardNavigationGestures
        />
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#FBF6EA' },
  webview: { flex: 1 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24 },
  errorText: { fontSize: 15, color: '#4A4438', textAlign: 'center', marginBottom: 16 },
  retryBtn: { backgroundColor: '#1B2A4A', paddingVertical: 12, paddingHorizontal: 24, borderRadius: 10 },
  retryText: { color: '#fff', fontWeight: '700' },
  loadingOverlay: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, alignItems: 'center', justifyContent: 'center', backgroundColor: '#FBF6EA' },
});
