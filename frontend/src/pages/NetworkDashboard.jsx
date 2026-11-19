import { useEffect, useRef, useState } from 'react'
import { FileArchive, FolderOpen, Upload, X, RefreshCw, Trash2 } from 'lucide-react'
import {
  deleteNetworkScan,
  getNetworkAlerts,
  getNetworkIps,
  getNetworkScan,
  listNetworkScans,
  uploadNetworkCaptures,
} from '../api/client'
import LoadingSpinner from '../components/LoadingSpinner'
import { Chart as ChartJS, ArcElement, Tooltip } from 'chart.js'
import { Doughnut } from 'react-chartjs-2'

ChartJS.register(ArcElement, Tooltip)

const MAX_SIZE = 50 * 1024 * 1024
const SUPPORTED = ['pcap', 'pcapng']
const PROTOCOL_COLORS = ['#2563eb', '#8b5cf6', '#f59e0b', '#94a3b8']

const statusClass = {
  queued: 'status-queued',
  running: 'status-running',
  completed: 'status-complete',
  failed: 'status-failed',
}

function isSupported(file) {
  return SUPPORTED.includes(file.name.split('.').pop()?.toLowerCase())
}

function formatPorts(ports = []) {
  if (ports.length === 0) return 'None'
  const visible = ports.slice(0, 12).join(', ')
  return ports.length > 12 ? `${visible}, +${ports.length - 12} more` : visible
}

async function fetchAllNetworkAlerts(scanId) {
  const alerts = []
  let skip = 0
  let page
  do {
    page = await getNetworkAlerts(scanId, skip, 1000)
    alerts.push(...page)
    skip += page.length
  } while (page.length === 1000)
  return alerts
}

async function fetchAllNetworkIps(scanId) {
  const hosts = []
  let skip = 0
  let total = 0
  while (skip < total || skip === 0) {
    const page = await getNetworkIps(scanId, 'all', skip, 200)
    if (page.ips.length === 0) break
    hosts.push(...page.ips)
    total = page.total
    skip += page.ips.length
  }
  return hosts
}

function createIpSummary(ip) {
  return {
    ip,
    suspicious: false,
    alert_types: new Set(),
    packets_sent: 0,
    packets_received: 0,
    bytes_sent: 0,
    bytes_received: 0,
    protocols: { tcp: 0, udp: 0, icmp: 0, other: 0 },
    tcp_source_ports: new Set(),
    tcp_destination_ports: new Set(),
    udp_source_ports: new Set(),
    udp_destination_ports: new Set(),
    first_seen: null,
    last_seen: null,
  }
}

export default function NetworkDashboard() {
  const [selectedFiles, setSelectedFiles] = useState([])
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [batchScans, setBatchScans] = useState([])
  const [batchScanIds, setBatchScanIds] = useState([])
  const [batchSummary, setBatchSummary] = useState(null)
  const [batchSummaryLoading, setBatchSummaryLoading] = useState(false)
  const [deletingScanId, setDeletingScanId] = useState(null)
  const [selectedScan, setSelectedScan] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [ipModal, setIpModal] = useState(null)
  const [ipRows, setIpRows] = useState([])
  const [ipTotal, setIpTotal] = useState(0)
  const [inventoryTotal, setInventoryTotal] = useState(0)
  const [ipPage, setIpPage] = useState(0)
  const [ipLoading, setIpLoading] = useState(false)
  const [ipError, setIpError] = useState('')
  const fileInput = useRef(null)
  const folderInput = useRef(null)

  const loadHistory = async () => {
    setHistoryLoading(true)
    try {
      const scans = await listNetworkScans(0, 30)
      setHistory(scans)
      return scans
    } finally {
      setHistoryLoading(false)
    }
  }

  const loadScan = async (id) => {
    const scan = await getNetworkScan(id)
    setBatchSummary(null)
    setSelectedScan(scan)
    if (scan.status === 'completed') setAlerts(await getNetworkAlerts(id))
    else setAlerts([])
  }

  const loadIpPage = async (scanId, kind, page) => {
    setIpLoading(true)
    setIpError('')
    if (selectedScan?.isBatch && batchSummary) {
      const hosts = batchSummary.ip_summaries.filter((host) => (
        kind === 'all' || (kind === 'suspicious' ? host.suspicious : !host.suspicious)
      ))
      setIpRows(hosts.slice(page * 100, (page + 1) * 100))
      setIpTotal(hosts.length)
      setInventoryTotal(batchSummary.ip_summaries.length)
      setIpPage(page)
      setIpLoading(false)
      return
    }

    try {
      const result = await getNetworkIps(scanId, kind, page * 100, 100)
      setIpRows(result.ips)
      setIpTotal(result.total)
      setInventoryTotal(result.inventory_total)
      setIpPage(page)
    } catch (e) {
      setIpError(e.response?.data?.detail || 'Failed to load IP details')
      setIpRows([])
      setIpTotal(0)
      setInventoryTotal(0)
    } finally {
      setIpLoading(false)
    }
  }

  const openIpList = (kind) => {
    if (!selectedScan) return
    setIpModal(kind)
    loadIpPage(selectedScan.id, kind, 0)
  }

  const handleDeleteScan = async (scan) => {
    if (!window.confirm(`Delete "${scan.filename}" and all of its alerts and IP details?`)) return

    setError('')
    setDeletingScanId(scan.id)
    try {
      await deleteNetworkScan(scan.id)
      setHistory((current) => current.filter((item) => item.id !== scan.id))
      setBatchScans((current) => current.filter((item) => item.id !== scan.id))
      setBatchScanIds((current) => current.filter((id) => id !== scan.id))
      if (selectedScan?.isBatch && batchScanIds.includes(scan.id)) {
        setSelectedScan(null)
        setBatchSummary(null)
        setAlerts([])
      }
      if (selectedScan?.id === scan.id) {
        setSelectedScan(null)
        setAlerts([])
        setIpModal(null)
        setIpRows([])
      }
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to delete network scan')
    } finally {
      setDeletingScanId(null)
    }
  }

  const handleViewAllResults = async () => {
    setBatchSummaryLoading(true)
    setError('')
    try {
      const scans = await Promise.all(batchScanIds.map((id) => getNetworkScan(id)))
      setBatchScans(scans)
      if (scans.some((scan) => ['queued', 'running'].includes(scan.status))) {
        throw new Error('Wait for all files to finish analyzing before combining results.')
      }

      const completedScans = scans.filter((scan) => scan.status === 'completed')
      if (completedScans.length === 0) {
        throw new Error('There are no completed files to combine.')
      }

      const totals = {
        total_packets: 0,
        tcp_packets: 0,
        udp_packets: 0,
        icmp_packets: 0,
        other_packets: 0,
      }
      const hostsByIp = new Map()
      const combinedAlerts = []

      for (const scan of completedScans) {
        const [alertsForScan, hostsForScan] = await Promise.all([
          fetchAllNetworkAlerts(scan.id),
          fetchAllNetworkIps(scan.id),
        ])

        Object.keys(totals).forEach((key) => {
          totals[key] += scan.packet_statistics?.[key] || 0
        })

        alertsForScan.forEach((alert) => {
          combinedAlerts.push({ ...alert, source_file: scan.filename })
          let host = hostsByIp.get(alert.source_ip)
          if (!host) {
            host = createIpSummary(alert.source_ip)
            hostsByIp.set(alert.source_ip, host)
          }
          host.suspicious = true
          host.alert_types.add(alert.alert_type)
        })

        hostsForScan.forEach((item) => {
          let host = hostsByIp.get(item.ip)
          if (!host) {
            host = createIpSummary(item.ip)
            hostsByIp.set(item.ip, host)
          }
          host.suspicious = host.suspicious || item.suspicious
          for (const type of item.alert_types || []) {
            host.alert_types.add(type)
          }
          for (const key of ['packets_sent', 'packets_received', 'bytes_sent', 'bytes_received']) {
            host[key] += item[key] || 0
          }
          for (const protocol of ['tcp', 'udp', 'icmp', 'other']) {
            host.protocols[protocol] += item.protocols?.[protocol] || 0
          }
          for (const key of ['tcp_source_ports', 'tcp_destination_ports', 'udp_source_ports', 'udp_destination_ports']) {
            for (const port of item[key] || []) {
              host[key].add(port)
            }
          }
          if (item.first_seen && (!host.first_seen || item.first_seen < host.first_seen)) {
            host.first_seen = item.first_seen
          }
          if (item.last_seen && (!host.last_seen || item.last_seen > host.last_seen)) {
            host.last_seen = item.last_seen
          }
        })
      }

      const ipSummaries = Array.from(hostsByIp.values())
        .map((host) => ({
          ...host,
          alert_types: Array.from(host.alert_types).sort(),
          tcp_source_ports: Array.from(host.tcp_source_ports).sort((a, b) => a - b),
          tcp_destination_ports: Array.from(host.tcp_destination_ports).sort((a, b) => a - b),
          udp_source_ports: Array.from(host.udp_source_ports).sort((a, b) => a - b),
          udp_destination_ports: Array.from(host.udp_destination_ports).sort((a, b) => a - b),
        }))
        .sort((a, b) => a.ip.localeCompare(b.ip))

      totals.unique_source_ips = ipSummaries.filter((host) => host.packets_sent > 0).length
      totals.unique_destination_ips = ipSummaries.filter((host) => host.packets_received > 0).length
      totals.unique_ip_addresses = ipSummaries.length
      totals.alert_count = combinedAlerts.length
      totals.suspicious_ip_count = ipSummaries.filter((host) => host.suspicious).length

      const failedCount = scans.length - completedScans.length
      const filename = `Combined results (${completedScans.length} file${completedScans.length === 1 ? '' : 's'})`
      const summary = {
        filename,
        packet_statistics: totals,
        ip_summaries: ipSummaries,
        failed_count: failedCount,
      }

      setBatchSummary(summary)
      setAlerts(combinedAlerts)
      setSelectedScan({
        id: 'batch',
        filename,
        status: 'completed',
        packet_statistics: totals,
        isBatch: true,
      })
      setIpModal(null)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Failed to combine batch results')
    } finally {
      setBatchSummaryLoading(false)
    }
  }

  useEffect(() => {
    loadHistory().catch(() => setError('Failed to load network scan history'))
  }, [])

  useEffect(() => {
    if (batchScanIds.length === 0) return undefined

    let interval
    let cancelled = false
    const refreshBatch = async () => {
      try {
        const scans = await Promise.all(batchScanIds.map((id) => getNetworkScan(id)))
        if (cancelled) return

        setBatchScans(scans)
        const updatedById = new Map(scans.map((scan) => [scan.id, scan]))
        setHistory((current) => current.map((scan) => updatedById.get(scan.id) || scan))

        if (scans.every((scan) => !['queued', 'running'].includes(scan.status))) {
          clearInterval(interval)
        }
      } catch (e) {
        if (!cancelled) {
          setError(e.response?.data?.detail || 'Failed to refresh upload batch status')
          clearInterval(interval)
        }
      }
    }

    refreshBatch()
    interval = setInterval(refreshBatch, 2000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [batchScanIds])

  useEffect(() => {
    if (!selectedScan || !['queued', 'running'].includes(selectedScan.status)) return
    const interval = setInterval(async () => {
      try {
        const scan = await getNetworkScan(selectedScan.id)
        setSelectedScan(scan)
        if (scan.status !== 'queued' && scan.status !== 'running') {
          clearInterval(interval)
          await loadHistory()
          if (scan.status === 'completed') setAlerts(await getNetworkAlerts(scan.id))
        }
      } catch (e) {
        clearInterval(interval)
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [selectedScan?.id, selectedScan?.status])

  const addFiles = (fileList) => {
    const incoming = Array.from(fileList)
    const supported = []
    let ignored = 0

    incoming.forEach((file) => {
      if (!isSupported(file)) {
        ignored += 1
      } else if (file.size > MAX_SIZE) {
        setError(`${file.name}: file exceeds the 50 MB limit`)
      } else {
        const filePath = file.webkitRelativePath || file.name
        const key = `${filePath}-${file.size}-${file.lastModified}`
        if (!selectedFiles.some((item) =>
          `${item.webkitRelativePath || item.name}-${item.size}-${item.lastModified}` === key
        )) {
          supported.push(file)
        }
      }
    })
    setSelectedFiles((current) => [...current, ...supported])
    if (ignored > 0) setMessage(`${ignored} unsupported file(s) ignored. Only .pcap and .pcapng are accepted.`)
  }

  const removeFile = (index) => setSelectedFiles((files) => files.filter((_, i) => i !== index))

  const handleUpload = async () => {
    if (selectedFiles.length === 0) {
      setError('Select at least one PCAP or PCAPNG file')
      return
    }
    setError('')
    setMessage('')
    setUploading(true)
    setProgress(0)
    try {
      const result = await uploadNetworkCaptures(selectedFiles, (event) => {
        if (event.total) setProgress(Math.round((event.loaded * 100) / event.total))
      })
      setMessage(`${result.scans.length} capture(s) queued for analysis`)
      setBatchScans(result.scans)
      setBatchScanIds(result.scans.map((scan) => scan.id))
      setBatchSummary(null)
      setSelectedFiles([])
      await loadHistory()
      await loadScan(result.scans[0].id)
    } catch (e) {
      setError(e.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const stats = selectedScan?.packet_statistics || {}
  const uniqueIps = stats.unique_ip_addresses
    ?? ((stats.unique_source_ips || 0) + (stats.unique_destination_ips || 0))
  const suspiciousIps = stats.suspicious_ip_count || 0
  const normalIps = Math.max(0, uniqueIps - suspiciousIps)
  const protocolEntries = [
    { label: 'TCP', value: stats.tcp_packets || 0 },
    { label: 'UDP', value: stats.udp_packets || 0 },
    { label: 'ICMP', value: stats.icmp_packets || 0 },
    { label: 'Other', value: stats.other_packets || 0 },
  ]
  const protocolTotal = protocolEntries.reduce((total, entry) => total + entry.value, 0)
  const protocolChartData = {
    labels: protocolTotal ? protocolEntries.map((entry) => entry.label) : ['No packets'],
    datasets: [{
      data: protocolTotal ? protocolEntries.map((entry) => entry.value) : [1],
      backgroundColor: protocolTotal ? PROTOCOL_COLORS : ['#e2e8f0'],
      borderColor: '#ffffff',
      borderWidth: 4,
      hoverOffset: 8,
    }],
  }
  const protocolChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    plugins: {
      legend: { display: false },
      tooltip: {
        enabled: protocolTotal > 0,
        callbacks: {
          label: (context) => {
            const percentage = protocolTotal ? ((context.raw / protocolTotal) * 100).toFixed(1) : 0
            return ` ${context.label}: ${context.raw} packets (${percentage}%)`
          },
        },
      },
    },
  }
  const batchPending = batchScans.some((scan) => ['queued', 'running'].includes(scan.status))
  const batchHasCompleted = batchScans.some((scan) => scan.status === 'completed')
  const ipChartData = {
    labels: ['Suspicious', 'Not flagged'],
    datasets: [{
      data: uniqueIps > 0 ? [suspiciousIps, normalIps] : [1],
      backgroundColor: uniqueIps > 0 ? ['#ef4444', '#10b981'] : ['#e2e8f0'],
      borderColor: '#ffffff',
      borderWidth: 4,
      hoverOffset: 8,
    }],
  }
  const ipChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    rotation: uniqueIps > 0
      ? 270 - (suspiciousIps / uniqueIps) * 180
      : 0,
    plugins: {
      legend: { display: false },
      tooltip: {
        enabled: uniqueIps > 0,
        callbacks: { label: (context) => ` ${context.label}: ${context.raw} IPs` },
      },
    },
    onClick: (_event, elements) => {
      if (!elements.length || uniqueIps === 0) return
      openIpList(elements[0].index === 0 ? 'suspicious' : 'normal')
    },
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold text-surface-900">Network Lens</h1>
        <p className="mt-2 text-surface-500">
          Analyze captured network traffic and identify suspicious activities using our lightweight intrusion detection engine.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <section className="lg:col-span-3 glass p-6">
          <h2 className="font-display text-xl font-bold text-surface-900 mb-5">Upload Captures</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <button onClick={() => fileInput.current?.click()} className="btn-secondary h-24 flex-col">
              <Upload className="w-5 h-5" /> Upload Files
            </button>
            <button onClick={() => folderInput.current?.click()} className="btn-secondary h-24 flex-col">
              <FolderOpen className="w-5 h-5" /> Upload Folder
            </button>
            <input ref={fileInput} type="file" accept=".pcap,.pcapng" multiple hidden onChange={(e) => addFiles(e.target.files)} />
            <input ref={folderInput} type="file" accept=".pcap,.pcapng" webkitdirectory="" directory="" multiple hidden onChange={(e) => addFiles(e.target.files)} />
          </div>

          {selectedFiles.length > 0 && (
            <div className="mt-5 space-y-2">
              {selectedFiles.map((file, index) => (
                <div key={`${file.webkitRelativePath || file.name}-${file.size}-${file.lastModified}`} className="flex items-center justify-between rounded-xl border border-surface-200 px-4 py-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <FileArchive className="w-4 h-4 text-brand-600 shrink-0" />
                    <span className="text-sm font-medium text-surface-700 truncate">{file.webkitRelativePath || file.name}</span>
                    <span className="text-xs text-surface-400 shrink-0">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                  <button onClick={() => removeFile(index)} className="p-1 text-surface-400 hover:text-red-500" title="Remove file">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {uploading && (
            <div className="mt-5">
              <div className="h-2 rounded-full bg-surface-100 overflow-hidden">
                <div className="h-full bg-brand-600 transition-all" style={{ width: `${progress}%` }} />
              </div>
              <p className="mt-2 text-xs text-surface-500">Uploading... {progress}%</p>
            </div>
          )}
          {message && <p className="mt-4 text-sm text-brand-700">{message}</p>}
          {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

          <button onClick={handleUpload} disabled={uploading || selectedFiles.length === 0} className="btn-primary mt-5 w-full">
            {uploading ? 'Uploading...' : 'Analyze Network Traffic'}
          </button>
        </section>

        <section className="lg:col-span-2 glass p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-xl font-bold text-surface-900">Capture History</h2>
            <button onClick={loadHistory} className="btn-secondary px-3 py-1.5 text-xs"><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          </div>
          {historyLoading ? (
            <LoadingSpinner message="Loading captures..." />
          ) : history.length === 0 ? (
            <p className="text-sm text-surface-400 py-8 text-center">No network captures analyzed yet.</p>
          ) : (
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {history.map((scan) => {
                const active = ['queued', 'running'].includes(scan.status)
                return (
                  <div key={scan.id} className={`flex items-center gap-2 rounded-xl border p-2 transition-colors ${selectedScan?.id === scan.id ? 'border-brand-300 bg-brand-50' : 'border-surface-200 hover:bg-surface-50'}`}>
                    <button
                      type="button"
                      onClick={() => loadScan(scan.id).catch(() => setError('Failed to load scan'))}
                      className="flex-1 min-w-0 text-left px-2 py-1"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-sm font-medium text-surface-700 truncate">{scan.filename}</span>
                        <span className={statusClass[scan.status]}>{scan.status}</span>
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDeleteScan(scan)}
                      disabled={active || deletingScanId === scan.id}
                      title={active ? 'Wait for analysis to finish before deleting' : 'Delete this scan and its results'}
                      aria-label={`Delete ${scan.filename}`}
                      className="p-2 rounded-lg text-surface-400 hover:text-red-600 hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      </div>

      {batchScans.length > 0 && (
        <section className="glass p-6">
          <div className="flex items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="font-display text-xl font-bold text-surface-900">Latest Upload Batch</h2>
              <p className="text-sm text-surface-500 mt-1">
                Packet totals are summed, IPs are deduplicated, and alerts remain listed per capture.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="tool-badge">{batchScans.length} file{batchScans.length === 1 ? '' : 's'}</span>
              <button
                type="button"
                onClick={handleViewAllResults}
                disabled={batchSummaryLoading || batchPending || !batchHasCompleted}
                title={batchPending ? 'Wait for all files to finish analyzing' : 'Combine completed files'}
                className="btn-primary py-2 px-3 text-xs"
              >
                {batchSummaryLoading ? 'Combining...' : 'View All Results'}
              </button>
            </div>
          </div>
          {batchPending && (
            <p className="text-xs text-surface-500 mb-3">Combined results will be available when batch analysis finishes.</p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {batchScans.map((scan) => (
              <div key={scan.id} className="rounded-xl border border-surface-200 p-4">
                <div className="flex items-start justify-between gap-3">
                  <button
                    type="button"
                    onClick={() => loadScan(scan.id).catch(() => setError(`Failed to load ${scan.filename}`))}
                    className="text-left min-w-0"
                    title="View this capture's results"
                  >
                    <span className="block text-sm font-semibold text-surface-800 break-all">{scan.filename}</span>
                  </button>
                  <span className={statusClass[scan.status]}>{scan.status}</span>
                </div>
                {scan.status === 'completed' && (
                  <p className="mt-2 text-xs text-surface-500">
                    {scan.packet_statistics?.total_packets ?? 0} packets · {scan.alert_count} alerts
                  </p>
                )}
                {scan.status === 'failed' && (
                  <p className="mt-2 text-xs text-red-600">{scan.error_message || 'Analysis failed'}</p>
                )}
                <button
                  type="button"
                  onClick={() => loadScan(scan.id).catch(() => setError(`Failed to load ${scan.filename}`))}
                  className="btn-secondary mt-3 w-full py-2 text-xs"
                >
                  View Results
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {selectedScan && (
        <section className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-xl font-bold text-surface-900">{selectedScan.filename}</h2>
              <p className="text-sm text-surface-400">Status: {selectedScan.status}</p>
            </div>
          </div>

          {['queued', 'running'].includes(selectedScan.status) && <LoadingSpinner message="Analyzing capture..." />}
          {selectedScan.status === 'failed' && <div className="glass p-6 text-red-600">{selectedScan.error_message || 'Analysis failed'}</div>}
          {selectedScan.status === 'completed' && (
            <>
              {selectedScan.isBatch && batchSummary?.failed_count > 0 && (
                <div className="glass p-4 border-l-4 border-amber-400 bg-amber-50 text-amber-700 text-sm">
                  {batchSummary.failed_count} file{batchSummary.failed_count === 1 ? '' : 's'} failed and were excluded from the combined totals.
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div className="stat-card">
                  <span className="text-xs font-bold uppercase tracking-wide text-surface-400">Total Packets</span>
                  <span className="text-2xl font-bold text-surface-900">{stats.total_packets || 0}</span>
                </div>
                <div className="stat-card">
                  <span className="text-xs font-bold uppercase tracking-wide text-surface-400">Total Alerts</span>
                  <span className="text-2xl font-bold text-surface-900">{stats.alert_count || 0}</span>
                </div>
              </div>

              <section className="glass p-6">
                <div className="text-center mb-5">
                  <h3 className="font-display text-lg font-bold text-surface-900">IP Address Breakdown</h3>
                  <p className="mt-1 text-xs text-surface-500">
                    Suspicious means an IP triggered an IDS rule; not flagged does not guarantee safe.
                  </p>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-[1fr_240px_1fr] items-center gap-8 max-w-5xl mx-auto">
                  <button
                    type="button"
                    onClick={() => openIpList('suspicious')}
                    className="relative order-2 md:order-1 w-full rounded-2xl border border-red-100 bg-red-50/60 p-5 text-left hover:bg-red-50 hover:border-red-200 transition-colors"
                    title="View suspicious IP addresses"
                  >
                    <span className="block text-xs font-bold uppercase tracking-wide text-red-600">Suspicious IPs</span>
                    <span className="block mt-1 text-3xl font-bold text-surface-900">{suspiciousIps}</span>
                    <span className="block mt-1 text-xs text-surface-500">Click to inspect detected IPs</span>
                    <span aria-hidden="true" className="hidden md:block absolute top-1/2 -right-8 w-8 border-t-2 border-red-300" />
                  </button>

                  <div className="relative order-1 md:order-2 w-full h-60">
                    <Doughnut
                      data={ipChartData}
                      options={ipChartOptions}
                      aria-label={`${uniqueIps} unique IP addresses: ${suspiciousIps} suspicious and ${normalIps} not flagged`}
                    />
                    <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-3xl font-bold text-surface-900">{uniqueIps}</span>
                      <span className="text-xs text-surface-500">unique IPs</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => openIpList('normal')}
                    className="relative order-3 w-full rounded-2xl border border-emerald-100 bg-emerald-50/60 p-5 text-left hover:bg-emerald-50 hover:border-emerald-200 transition-colors"
                    title="View IP addresses not flagged by IDS rules"
                  >
                    <span className="block text-xs font-bold uppercase tracking-wide text-emerald-700">Not Flagged</span>
                    <span className="block mt-1 text-3xl font-bold text-surface-900">{normalIps}</span>
                    <span className="block mt-1 text-xs text-surface-500">Click to inspect other IPs</span>
                    <span aria-hidden="true" className="hidden md:block absolute top-1/2 -left-8 w-8 border-t-2 border-emerald-300" />
                  </button>
                </div>
              </section>

              <div className="glass p-6">
                <h3 className="font-display text-lg font-bold mb-5">Protocol Statistics</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center max-w-3xl mx-auto">
                  <div className="relative w-full h-60">
                    <Doughnut data={protocolChartData} options={protocolChartOptions} />
                    <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-3xl font-bold text-surface-900">{stats.total_packets || 0}</span>
                      <span className="text-xs text-surface-500">total packets</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    {protocolEntries.map((entry, index) => (
                      <div key={entry.label} className="rounded-xl border border-surface-200 bg-surface-50 p-4">
                        <div className="flex items-center gap-2">
                          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PROTOCOL_COLORS[index] }} />
                          <span className="text-xs font-bold uppercase tracking-wide text-surface-500">{entry.label}</span>
                        </div>
                        <p className="mt-2 text-xl font-bold text-surface-900">{entry.value}</p>
                        <p className="text-xs text-surface-400">
                          {protocolTotal ? `${((entry.value / protocolTotal) * 100).toFixed(1)}% of packets` : '0% of packets'}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="glass overflow-hidden">
                <h3 className="font-display text-lg font-bold p-6 pb-3">Detected Alerts</h3>
                {alerts.length === 0 ? (
                  <div className="p-10 text-center text-surface-500">No suspicious activity detected</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-surface-50 border-y border-surface-200 text-xs uppercase text-surface-500">
                        <tr>
                          {selectedScan.isBatch && <th className="p-4 text-left">Capture</th>}
                          <th className="p-4 text-left">Alert</th>
                          <th className="p-4 text-left">Severity</th>
                          <th className="p-4 text-left">Source</th>
                          <th className="p-4 text-left">Destination</th>
                          <th className="p-4 text-left">Evidence</th>
                          <th className="p-4 text-left">Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {alerts.map((alert) => (
                          <tr key={alert.id} className="border-b border-surface-100">
                            {selectedScan.isBatch && <td className="p-4 text-xs text-surface-600">{alert.source_file}</td>}
                            <td className="p-4 font-semibold">{alert.alert_type}</td>
                            <td className="p-4">
                              <span className={alert.severity === 'High' ? 'badge-critical' : alert.severity === 'Medium' ? 'badge-warning' : 'badge-info'}>{alert.severity}</span>
                            </td>
                            <td className="p-4 font-mono text-xs">{alert.source_ip}</td>
                            <td className="p-4 font-mono text-xs">{alert.destination_ip || '-'}</td>
                            <td className="p-4 text-xs text-surface-600">
                              {alert.evidence.destination_ports
                                ? `${alert.evidence.unique_destination_port_count} ports: ${alert.evidence.destination_ports.slice(0, 10).join(', ')}`
                                : alert.evidence.destination_port
                                  ? `${alert.evidence.destination_ip_count} IPs on TCP port ${alert.evidence.destination_port}: ${alert.evidence.destination_ips.slice(0, 10).join(', ')}`
                                  : `${alert.evidence.packet_count} packets / ${alert.evidence.time_window_seconds}s`}
                            </td>
                            <td className="p-4 text-surface-600 max-w-md">{alert.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      )}

      {ipModal && (
        <div
          className="fixed inset-0 z-[60] bg-slate-900/50 p-4 flex items-center justify-center"
          onClick={() => setIpModal(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="ip-modal-title"
            className="glass w-full max-w-6xl max-h-[85vh] overflow-hidden bg-white shadow-xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4 p-5 border-b border-surface-200">
              <div>
                <h2 id="ip-modal-title" className="font-display text-xl font-bold text-surface-900">
                  {ipModal === 'suspicious'
                    ? 'Suspicious IP Addresses'
                    : ipModal === 'normal'
                      ? 'Not Flagged IP Addresses'
                      : 'Unique IP Addresses'}
                </h2>
                <p className="mt-1 text-sm text-surface-500">
                  Packet counts, observed protocols and ports, capture times, and matched detection rules.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIpModal(null)}
                className="p-2 rounded-lg text-surface-400 hover:text-surface-700 hover:bg-surface-100"
                aria-label="Close IP details"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {ipLoading ? (
              <div className="p-8"><LoadingSpinner message="Loading IP details..." /></div>
            ) : ipError ? (
              <p className="p-6 text-sm text-red-600">{ipError}</p>
            ) : ipRows.length === 0 ? (
              <p className="p-8 text-center text-sm text-surface-500">
                {inventoryTotal === 0 && uniqueIps > 0
                  ? 'IP details were not saved for this older scan. Re-upload the capture to generate its IP inventory.'
                  : ipModal === 'suspicious'
                    ? 'No suspicious IP addresses were detected.'
                    : ipModal === 'normal'
                      ? 'No unflagged IP addresses are in this capture.'
                      : 'No IP addresses were found in this capture.'}
              </p>
            ) : (
              <>
                <div className="overflow-auto max-h-[calc(85vh-150px)]">
                  <table className="w-full min-w-[1050px] text-sm">
                    <thead className="sticky top-0 bg-surface-50 border-b border-surface-200 text-xs uppercase text-surface-500">
                      <tr>
                        <th className="p-3 text-left">IP Address</th>
                        <th className="p-3 text-left">Packets / Bytes Sent &amp; Received</th>
                        <th className="p-3 text-left">Protocol Counts</th>
                        <th className="p-3 text-left">Observed Ports</th>
                        <th className="p-3 text-left">First / Last Seen</th>
                        <th className="p-3 text-left">Detection</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ipRows.map((host) => {
                        const protocols = host.protocols || {}
                        return (
                          <tr key={host.ip} className="align-top border-b border-surface-100">
                            <td className="p-3 font-mono font-semibold text-surface-800">
                              {host.ip}
                              {host.suspicious && <span className="badge-critical ml-2">Suspicious</span>}
                            </td>
                            <td className="p-3 text-surface-600">
                              <div>Sent: {host.packets_sent} / {host.bytes_sent} B</div>
                              <div>Received: {host.packets_received} / {host.bytes_received} B</div>
                              <div>Total: {host.packets_sent + host.packets_received} packets</div>
                            </td>
                            <td className="p-3 text-surface-600">
                              <div>TCP {protocols.tcp || 0} · UDP {protocols.udp || 0}</div>
                              <div>ICMP {protocols.icmp || 0} · Other {protocols.other || 0}</div>
                            </td>
                            <td className="p-3 text-xs text-surface-600">
                              <div>TCP out: {formatPorts(host.tcp_source_ports)}</div>
                              <div>TCP in: {formatPorts(host.tcp_destination_ports)}</div>
                              <div>UDP out: {formatPorts(host.udp_source_ports)}</div>
                              <div>UDP in: {formatPorts(host.udp_destination_ports)}</div>
                            </td>
                            <td className="p-3 text-xs text-surface-600">
                              <div>{host.first_seen ? new Date(host.first_seen).toLocaleString() : '-'}</div>
                              <div>{host.last_seen ? new Date(host.last_seen).toLocaleString() : '-'}</div>
                            </td>
                            <td className="p-3 text-xs text-surface-600">
                              {host.alert_types?.length ? host.alert_types.join(', ') : 'None'}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-center justify-between border-t border-surface-200 p-4">
                  <span className="text-xs text-surface-500">
                    Showing {ipPage * 100 + 1}–{Math.min((ipPage + 1) * 100, ipTotal)} of {ipTotal} addresses
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={ipPage === 0 || ipLoading}
                      onClick={() => loadIpPage(selectedScan.id, ipModal, ipPage - 1)}
                      className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button
                      type="button"
                      disabled={(ipPage + 1) * 100 >= ipTotal || ipLoading}
                      onClick={() => loadIpPage(selectedScan.id, ipModal, ipPage + 1)}
                      className="btn-secondary px-3 py-1.5 text-xs disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </div>
  )
}
