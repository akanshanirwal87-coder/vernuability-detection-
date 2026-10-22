import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { Toaster } from 'sonner';

export const AppShell: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-background text-slate-100 flex">
      {/* Persistent Sidebar */}
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />

      {/* Main Content Area */}
      <div 
        className={`flex-1 flex flex-col min-h-screen transition-all duration-300 ${
          collapsed ? 'ml-20' : 'ml-64'
        }`}
      >
        <Header />
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          <Outlet />
        </main>
      </div>

      <Toaster 
        theme="dark" 
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#111827',
            borderColor: '#1E293B',
            color: '#F8FAFC',
          }
        }}
      />
    </div>
  );
};

