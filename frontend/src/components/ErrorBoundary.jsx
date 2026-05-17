import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

/**
 * ErrorBoundary - React Error Boundary component
 * 
 * Catches errors anywhere in the child component tree and displays
 * a fallback UI instead of crashing the entire app.
 * 
 * Security: Logs full errors to console but shows safe UI to users.
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorCount: 0
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Log full error details for debugging
    console.error('Error caught by ErrorBoundary:', error, errorInfo);
    
    this.setState(prevState => ({
      error,
      errorInfo,
      errorCount: prevState.errorCount + 1
    }));

    // Optional: Send error to monitoring service
    // trackError(error, errorInfo);
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={styles.container}>
          <div style={styles.errorBox}>
            <AlertTriangle size={48} style={styles.icon} />
            <h1 style={styles.title}>Oops! Something went wrong</h1>
            <p style={styles.message}>
              The application encountered an unexpected error. 
              Please try refreshing the page or contact support if the problem persists.
            </p>
            
            {import.meta.env.DEV && this.state.error && (
              <details style={styles.details}>
                <summary style={styles.summary}>
                  Error Details (Development Only)
                </summary>
                <pre style={styles.errorText}>
                  {this.state.error.toString()}
                  {'\n\n'}
                  {this.state.errorInfo?.componentStack}
                </pre>
              </details>
            )}

            <button
              onClick={this.handleReset}
              style={styles.resetButton}
              onMouseEnter={(e) => e.target.style.background = '#0058a0'}
              onMouseLeave={(e) => e.target.style.background = '#0070b8'}
            >
              <RotateCcw size={16} style={{ marginRight: '8px' }} />
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #08090e 0%, #0d1118 100%)',
    padding: '20px',
    fontFamily: 'Manrope, sans-serif',
  },
  errorBox: {
    background: 'rgba(13, 17, 24, 0.8)',
    border: '1px solid rgba(255, 61, 77, 0.3)',
    borderRadius: '16px',
    padding: '40px',
    maxWidth: '600px',
    width: '100%',
    textAlign: 'center',
  },
  icon: {
    color: '#ff3d4d',
    marginBottom: '20px',
  },
  title: {
    color: '#f0f4f8',
    fontSize: '24px',
    marginBottom: '12px',
    fontWeight: 600,
  },
  message: {
    color: '#a8b5c8',
    fontSize: '14px',
    lineHeight: '1.6',
    marginBottom: '24px',
  },
  details: {
    marginTop: '16px',
    marginBottom: '24px',
    textAlign: 'left',
  },
  summary: {
    color: '#4db8ff',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 600,
    padding: '8px',
    borderRadius: '8px',
    background: 'rgba(13, 159, 255, 0.1)',
    marginBottom: '8px',
  },
  errorText: {
    background: 'rgba(0, 0, 0, 0.3)',
    color: '#ff3d4d',
    padding: '12px',
    borderRadius: '8px',
    fontSize: '11px',
    overflow: 'auto',
    maxHeight: '200px',
    fontFamily: 'IBM Plex Mono, monospace',
    margin: '8px 0',
  },
  resetButton: {
    background: '#0070b8',
    color: '#f0f4f8',
    border: 'none',
    borderRadius: '8px',
    padding: '10px 20px',
    fontSize: '14px',
    fontWeight: 600,
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    gap: '8px',
    transition: 'background 150ms ease-in-out',
  },
};

export default ErrorBoundary;
