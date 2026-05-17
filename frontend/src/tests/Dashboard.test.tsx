import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Dashboard from '../components/Dashboard';
import { AgenticService } from '../services/api';

// Mock the API service
jest.mock('../services/api');

describe('Dashboard Component Integration', () => {
  test('renders threat globe and statistics cards', () => {
    render(<Dashboard />);
    expect(screen.getByText(/Agentic Threat Monitor/i)).toBeInTheDocument();
    expect(screen.getByText(/Live Network Feed/i)).toBeInTheDocument();
  });

  test('triggers detection workflow when manual flow is submitted', async () => {
    const mockDetect = AgenticService.detect as jest.Mock;
    mockDetect.mockResolvedValue({
      status: 'success',
      threat_level: 'Critical',
      reasoning: 'Simulated brute force detected.'
    });

    render(<Dashboard />);
    
    // Simulate clicking "Test Flow" button
    const testButton = screen.getByRole('button', { name: /Simulate Attack/i });
    fireEvent.click(testButton);

    await waitFor(() => {
      expect(screen.getByText(/Simulated brute force detected/i)).toBeInTheDocument();
      expect(screen.getByText(/Critical/i)).toBeInTheDocument();
    });
  });

  test('displays error message on API failure', async () => {
    AgenticService.detect.mockRejectedValue(new Error('Network error'));
    
    render(<Dashboard />);
    fireEvent.click(screen.getByRole('button', { name: /Simulate Attack/i }));

    await waitFor(() => {
      expect(screen.getByText(/Failed to process flow/i)).toBeInTheDocument();
    });
  });
});
