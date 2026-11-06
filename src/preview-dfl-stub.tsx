// Browser preview stub for decky-frontend-lib.
// Provides minimal, styled stand-ins for the DFL components used by
// src/index.tsx so the UI runs in a plain browser during development.

import React from 'react';

const boxStyle: React.CSSProperties = {
  border: '1px solid #3a3f4b',
  borderRadius: '6px',
  padding: '10px 14px',
  marginBottom: '8px',
  background: 'rgba(255,255,255,0.04)'
};

export function PanelSection(props: { title?: string; desc?: string; children?: React.ReactNode }) {
  return (
    <div style={{ marginBottom: '16px' }}>
      {props.title && (
        <h2 style={{ fontSize: '15px', fontWeight: 600, margin: '0 0 8px', color: '#dfe3e8' }}>
          {props.title}
        </h2>
      )}
      {props.desc && <p style={{ fontSize: '12px', color: '#9aa2ad', margin: '0 0 8px' }}>{props.desc}</p>}
      {props.children}
    </div>
  );
}

export function PanelSectionRow(props: { children?: React.ReactNode }) {
  return <div style={boxStyle}>{props.children}</div>;
}

export function Field(props: { label?: string; description?: string; children?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
      <span style={{ fontSize: '13px', color: '#c7ccd4' }}>{props.label}</span>
      {props.children}
    </div>
  );
}

export function ButtonItem(props: {
  layout?: string;
  onClick?: () => void;
  disabled?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <button
      onClick={props.onClick}
      disabled={props.disabled}
      style={{
        padding: '8px 14px',
        borderRadius: '4px',
        border: '1px solid #5a6272',
        background: props.disabled ? '#2a2f3a' : '#3d4453',
        color: props.disabled ? '#6b7280' : '#e8eaee',
        cursor: props.disabled ? 'not-allowed' : 'pointer',
        fontSize: '13px',
        marginTop: '6px'
      }}
    >
      {props.children}
    </button>
  );
}

export function TextField(props: {
  label?: string;
  value?: string;
  onChange?: (e: any) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <label style={{ display: 'block', fontSize: '13px', color: '#c7ccd4' }}>
      {props.label}
      <input
        value={props.value ?? ''}
        onChange={props.onChange}
        placeholder={props.placeholder}
        disabled={props.disabled}
        style={{
          display: 'block',
          width: '100%',
          marginTop: '4px',
          padding: '6px 10px',
          borderRadius: '4px',
          border: '1px solid #3a3f4b',
          background: '#1b1e25',
          color: '#e8eaee',
          fontSize: '13px',
          boxSizing: 'border-box'
        }}
      />
    </label>
  );
}

export function DropdownItem(props: {
  label?: string;
  menuLabel?: string;
  selectedOption?: string;
  rgOptions?: Array<{ data: string; label: string }>;
  onChange?: (option: { data: string; label: string }) => void;
}) {
  const selected = props.rgOptions?.find((o) => o.data === props.selectedOption) ?? props.rgOptions?.[0];
  return (
    <label style={{ display: 'block', fontSize: '13px', color: '#c7ccd4' }}>
      {props.label}
      <select
        value={selected?.data ?? ''}
        onChange={(e) => {
          // Option data may be numeric (channel numbers) while the DOM
          // value is always a string; compare coerced values.
          const opt = props.rgOptions?.find((o) => String(o.data) === String(e.target.value));
          if (opt) props.onChange?.(opt);
        }}
        style={{
          display: 'block',
          width: '100%',
          marginTop: '4px',
          padding: '6px 8px',
          borderRadius: '4px',
          border: '1px solid #3a3f4b',
          background: '#1b1e25',
          color: '#e8eaee',
          fontSize: '13px'
        }}
      >
        {props.rgOptions?.map((o) => (
          <option key={o.data} value={o.data}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function ToggleField(props: {
  label?: string;
  description?: string;
  checked?: boolean;
  onChange?: (checked: boolean) => void;
}) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#c7ccd4' }}>
      <input
        type="checkbox"
        checked={props.checked ?? false}
        onChange={(e) => props.onChange?.(e.target.checked)}
      />
      <span>
        {props.label}
        {props.description && (
          <span style={{ display: 'block', fontSize: '11px', color: '#9aa2ad' }}>{props.description}</span>
        )}
      </span>
    </label>
  );
}

export const staticClasses: Record<string, string> = {};

export interface ServerAPI {
  callPluginMethod: (method: string, args?: Record<string, any>) => Promise<any>;
  [key: string]: any;
}

export function definePlugin(factory: (serverAPI: ServerAPI) => unknown) {
  return factory;
}
