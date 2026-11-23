export type AppView =
  'role-selection' | 'dashboard' | 'notification-apps' | 'notification-history';

export type DashboardModalType =
  | 'notification-permission'
  | 'usage-permission'
  | 'app-usage'
  | 'privacy-auth'
  | 'pair-device'
  | null;
