import { NButton, NSpace, NTag, NTooltip, type DataTableColumns } from 'naive-ui'
import {
	useModal,
	useTable,
	useDialog,
	useFormHooks,
	useModalHooks,
	useForm,
	useLoadingMask,
	useMessage,
	useSearch,
} from '@baota/naive-ui/hooks'
import { useError } from '@baota/hooks/error'
import { $t } from '@locales/index'
import { getDaysDiff } from '@baota/utils/date'

import { executeWorkflow } from '@/api/workflow'
import { useStore } from './useStore'

import type { CertItem, CertListParams, UpdateCertResult } from '@/types/cert'

const { handleError } = useError()
const { useFormTextarea } = useFormHooks()
const { fetchCertList, downloadExistingCert, deleteExistingCert, uploadNewCert, updateExistingCert, uploadForm, resetUploadForm, deleteBatchCerts } = useStore()
const { confirm } = useModalHooks()
/**
 * 计算证书剩余天数
 * @param cert 证书项
 * @returns 剩余天数，如果无法计算则返回 null
 */
const calculateRemainingDays = (cert: CertItem): number | null => {
	// 首先尝试使用后端提供的 end_day 字段
	const endDay = Number(cert.end_day)
	if (!isNaN(endDay) && endDay !== 0) {
		return endDay
	}

	// 如果 end_day 无效，则根据 end_time 计算
	if (cert.end_time) {
		try {
			const endTime = new Date(cert.end_time)
			const currentTime = new Date()

			// 检查日期是否有效
			if (isNaN(endTime.getTime())) {
				return null
			}

			// 计算剩余天数
			const endDay = getDaysDiff(currentTime, endTime)
			return endDay
		} catch (error) {
			console.warn('计算证书剩余天数失败:', error)
			return null
		}
	}

	return null
}

/**
 * useController
 * @description 证书管理业务逻辑控制器
 * @returns {object} 返回controller对象
 */
export const useController = () => {
	const checkedRowKeysRef = ref<(string | number)[]>([])
	const batchActionRef = ref<string>('delete')
	const statusFilterRef = ref<number | null>(null)

	const handleCheck: (rowKeys: (string | number)[]) => void = (rowKeys) => {
		checkedRowKeysRef.value = rowKeys
	}

	const handleBatchAction = async () => {
		if (checkedRowKeysRef.value.length === 0) {
			return
		}
		if (batchActionRef.value === 'delete') {
			const associated = data.value.filter(
				(r) => checkedRowKeysRef.value.includes(r.id.toString()) && (r.workflow_refs?.length ?? 0) > 0,
			)
			const warning = associated.length
				? `\n\n注意：其中 ${associated.length} 个证书正被工作流使用，删除后工作流可能无法正常运行。`
				: ''
			useDialog({
				title: '批量删除证书',
				content: `确定要删除选中的 ${checkedRowKeysRef.value.length} 个证书吗？${warning}`,
				onPositiveClick: async () => {
					try {
						await deleteBatchCerts(checkedRowKeysRef.value)
						checkedRowKeysRef.value = []
						await fetch()
					} catch (error) {
						handleError(error)
					}
				},
			})
		}
	}

	/**
	 * @description 创建表格列配置
	 * @returns {DataTableColumns<CertItem>} 返回表格列配置数组
	 */
	const createColumns = (): DataTableColumns<CertItem> => [
		{
			type: 'selection',
		},
		{
			title: $t('t_17_1745227838561'),
			key: 'domains',
			width: 200,
			ellipsis: {
				tooltip: true,
			},
		},
		{
			title: $t('t_18_1745227838154'),
			key: 'issuer',
			width: 200,
			ellipsis: {
				tooltip: true,
			},
		},
		{
			title: $t('t_21_1745227837972'),
			key: 'source',
			width: 100,
			render: (row: CertItem) => (row.source !== 'upload' ? $t('t_22_1745227838154') : $t('t_23_1745227838699')),
		},
		{
			title: $t('t_19_1745227839107'),
			key: 'end_day',
			width: 100,
			filterOptions: [
				{ label: '已过期', value: -1 },
				{ label: '即将过期', value: 1 },
				{ label: '正常', value: 2 },
			],
			filterMultiple: false,
			filter: (value: number, row: CertItem) => {
				const endDay = calculateRemainingDays(row)
				if (endDay === null) return false
				if (value === -1) return endDay <= 0
				if (value === 1) return endDay > 0 && endDay < 30
				if (value === 2) return endDay >= 30
				return true
			},
			render: (row: CertItem) => {
				const endDay = calculateRemainingDays(row)

				// 如果无法计算剩余天数，显示获取失败
				if (endDay === null) {
					return (
						<NTag round type="error" size="small">
						获取失败
						</NTag>
					);
				}

				// 根据剩余天数确定显示样式和文本
				const config = [
					[endDay <= 0, 'error', $t('t_0_1746001199409')],
					[endDay < 30, 'warning', $t('t_1_1745999036289', { days: endDay })],
					[endDay >= 30, 'success', $t('t_0_1745999035681', { days: endDay })],
				] as [boolean, 'success' | 'error' | 'warning' | 'default' | 'info' | 'primary', string][]

				const matchedConfig = config.find((item) => item[0])
				const [, type, text] = matchedConfig ?? ['default', 'error', '获取失败']

				return (
					<NTag round type={type} size="small">
						{text}
					</NTag>
				)
			},
		},
		{
			title: $t('t_20_1745227838813'),
			key: 'end_time',
			width: 150,
		},

		{
			title: $t('t_24_1745227839508'),
			key: 'create_time',
			width: 150,
		},
		{
			title: '关联工作流',
			key: 'workflow_refs',
			width: 120,
			render: (row: CertItem) => {
				const refs = row.workflow_refs ?? []
				if (!refs.length) return null
				return (
					<NTooltip trigger="hover">
						{{
							trigger: () => (
								<NTag round type="info" size="small">
									已关联 ({refs.length})
								</NTag>
							),
							default: () => refs.map((r) => r.name).join('、'),
						}}
					</NTooltip>
				)
			},
		},
		{
			title: $t('t_8_1745215914610'),
			key: 'actions',
			fixed: 'right' as const,
			align: 'right',
			width: 260,
			render: (row: CertItem) => (
				<NSpace justify="end">
					<NButton size="tiny" strong secondary type="primary" class="table-action-btn" onClick={() => openViewModal(row)}>
						查看
					</NButton>
					{row.source === 'upload' && (
						<NButton size="tiny" strong secondary type="warning" class="table-action-btn" onClick={() => openEditModal(row)}>
							编辑
						</NButton>
					)}
					<NButton size="tiny" strong secondary type="primary" class="table-action-btn" onClick={() => downloadExistingCert(row.id.toString())}>
						{$t('t_25_1745227838080')}
					</NButton>
					<NButton size="tiny" strong secondary type="error" class="table-action-btn-danger" onClick={() => handleDeleteCert(row)}>
						{$t('t_12_1745215914312')}
					</NButton>
				</NSpace>
			),
		},
	]

	/**
	 * 根据证书的到期天数确定行的 CSS 类名。
	 * @param row 当前行的数据对象，类型为 CertItem。
	 * @returns 返回一个字符串，表示行的 CSS 类名。
	 *          - 'bg-red-500/10'：如果证书已过期 (endDay <= 0)。
	 *          - 'bg-orange-500/10'：如果证书将在30天内过期 (0 < endDay < 30)。
	 *          - 空字符串：其他情况。
	 */
	const getRowClassName = (row: CertItem): string => {
		const endDay = calculateRemainingDays(row)

		// 如果无法计算剩余天数，不应用特殊样式
		if (endDay === null) {
			return ''
		}

		if (endDay <= 0) {
			return 'bg-red-500/10' // Tailwind class for light red background
		}
		if (endDay < 30) {
			return 'bg-orange-500/10' // Tailwind class for light orange background
		}
		return '' // 默认情况下没有额外的类
	}

	// 表格实例
	const { TableComponent, PageComponent, loading, param, data, fetch } = useTable<CertItem, CertListParams>({
		config: createColumns(),
		request: fetchCertList,
		defaultValue: { p: 1, limit: 10, search: '', status: 0 },
		alias: { page: 'p', pageSize: 'limit' },
		watchValue: ['p', 'limit', 'status'],
		storage: 'certManagePageSize',
		rowKey: (row) => row.id.toString(),
	})

	// 搜索实例
	const { SearchComponent } = useSearch({
		onSearch: (value) => {
			param.value.search = value
			fetch()
		},
	})

	// 监听筛选状态变化
	watch(
		() => statusFilterRef.value,
		(newStatus) => {
			param.value.status = newStatus === null ? 0 : newStatus
		}
	)

	/**
	 * @description 打开上传证书弹窗
	 */
	const openUploadModal = () => {
		useModal({
			title: $t('t_13_1745227838275'),
			area: 600,
			component: () => {
				const { UploadCertForm } = useUploadCertController()
				return <UploadCertForm labelPlacement="top" />
			},
			footer: true,
			onUpdateShow: (show) => {
				if (!show) fetch()
				resetUploadForm()
			},
		})
	}

	/**
	 * @description 删除证书
	 * @param {CertItem} cert - 证书对象
	 */
	const handleDeleteCert = async (row: CertItem) => {
		const refs = row.workflow_refs ?? []
		const content = refs.length
			? `此证书已被工作流「${refs.map((r) => r.name).join('、')}」使用，删除后工作流可能无法正常运行，确认删除？`
			: $t('t_30_1745227841739')
		useDialog({
			title: $t('t_29_1745227838410'),
			content,
			onPositiveClick: async () => {
				try {
					await deleteExistingCert(row.id.toString())
					await fetch()
				} catch (error) {
					handleError(error)
				}
			},
		})
	}

	/**
	 * @description 打开查看证书弹窗
	 * @param {CertItem} cert - 证书对象
	 */
	const openViewModal = (cert: CertItem) => {
		useModal({
			title: '查看证书信息',
			area: 600,
			component: () => {
				const { ViewCertForm } = useViewCertController(cert)
				return <ViewCertForm labelPlacement="top" />
			},
			footer: false,
		})
	}

	const openEditModal = (cert: CertItem) => {
		useModal({
			title: '编辑证书',
			area: 600,
			component: () => {
				const { EditCertForm } = useEditCertController(cert)
				return <EditCertForm labelPlacement="top" />
			},
			footer: true,
			onUpdateShow: (show) => {
				if (!show) fetch()
			},
		})
	}

	onMounted(() => fetch())

	return {
		loading,
		TableComponent,
		PageComponent,
		SearchComponent,
		getRowClassName,
		openUploadModal,
		openViewModal,
		checkedRowKeysRef,
		handleCheck,
		batchActionRef,
		handleBatchAction,
		statusFilterRef,
	}
}

/**
 * @description 上传证书控制器
 */
export const useUploadCertController = () => {
	const { open: openLoad, close: closeLoad } = useLoadingMask({ text: $t('t_0_1746667592819') })
	// 表单实例
	const { example, component, loading, fetch } = useForm({
		config: [
			useFormTextarea($t('t_34_1745227839375'), 'cert', { placeholder: $t('t_35_1745227839208'), rows: 6 }),
			useFormTextarea($t('t_36_1745227838958'), 'key', { placeholder: $t('t_37_1745227839669'), rows: 6 }),
		],
		request: uploadNewCert,
		defaultValue: uploadForm,
		rules: {
			cert: [{ required: true, message: $t('t_35_1745227839208'), trigger: 'input' }],
			key: [{ required: true, message: $t('t_37_1745227839669'), trigger: 'input' }],
		},
	})

	// 关联确认按钮
	confirm(async (close) => {
		try {
			openLoad()
			await fetch()
			close()
		} catch (error) {
			handleError(error)
		} finally {
			closeLoad()
		}
	})

	return {
		UploadCertForm: component,
		example,
		loading,
		fetch,
	}
}

/**
 * @description 查看证书控制器
 * @param {CertItem} cert - 证书对象
 */
export const useViewCertController = (cert: CertItem) => {
	/**
	 * @description 复制文本到剪贴板
	 * @param {string} text - 要复制的文本
	 */
	const copyToClipboard = async (text: string) => {
		const message = useMessage()
		try {
			await navigator.clipboard.writeText(text)
			message.success('复制成功')
		} catch (error) {
			// 降级方案：使用传统的复制方法
			try {
				const textArea = document.createElement('textarea')
				textArea.value = text
				document.body.appendChild(textArea)
				textArea.select()
				document.execCommand('copy')
				document.body.removeChild(textArea)
				message.success('复制成功')
			} catch (error) {
				message.error('复制失败')
			}
		}
	}

	// 合并证书内容（cert + issuer_cert）
	// const combinedCert = cert.cert + (cert.issuer_cert ? '\n' + cert.issuer_cert : '')
	const combinedCert = cert.cert

	// 表单实例
	const { component } = useForm({
		config: [
			useFormTextarea(
				$t('t_34_1745227839375'),
				'cert',
				{ placeholder: '', rows: 8, readonly: true },
				{},
				{
					suffix: [
						() => (
							<NButton size="tiny" type="primary" ghost onClick={() => copyToClipboard(combinedCert)}>
								{$t('t_4_1747984130327')}
							</NButton>
						),
					],
				},
			),
			useFormTextarea(
				$t('t_36_1745227838958'),
				'key',
				{ placeholder: '', rows: 8, readonly: true },
				{},
				{
					suffix: [
						() => (
							<NButton size="tiny" type="primary" ghost onClick={() => copyToClipboard(cert.key)}>
								{$t('t_4_1747984130327')}
							</NButton>
						),
					],
				},
			),
		],
		defaultValue: {
			cert: combinedCert,
			key: cert.key,
		},
	})

	return {
		ViewCertForm: component,
	}
}

/**
 * @description 编辑证书控制器（仅限手动上传的证书）
 * @param {CertItem} cert - 证书对象
 */
export const useEditCertController = (cert: CertItem) => {
	const { open: openLoad, close: closeLoad } = useLoadingMask({ text: '正在更新证书...' })
	const editForm = ref({ cert: cert.cert, key: cert.key })

	const { component, fetch } = useForm({
		config: [
			useFormTextarea($t('t_34_1745227839375'), 'cert', { placeholder: $t('t_35_1745227839208'), rows: 8 }),
			useFormTextarea($t('t_36_1745227838958'), 'key', { placeholder: $t('t_37_1745227839669'), rows: 8 }),
		],
		request: async (params: { cert: string; key: string }) => {
			return updateExistingCert({ id: cert.id.toString(), cert: params.cert, key: params.key })
		},
		defaultValue: editForm,
		rules: {
			cert: [{ required: true, message: $t('t_35_1745227839208'), trigger: 'input' }],
			key: [{ required: true, message: $t('t_37_1745227839669'), trigger: 'input' }],
		},
	})

	// 证书更新成功后，提示关联工作流是否立即触发执行
	const showWorkflowDialog = (workflows: Array<{ id: string; name: string }>) => {
		if (!workflows || workflows.length === 0) return
		const names = workflows.map((w) => w.name).join('、')
		useDialog({
			title: '证书已更新',
			content: `检测到以下工作流使用了此证书：${names}，是否立即触发执行？`,
			confirmText: '立即执行',
			cancelText: '稍后',
			onPositiveClick: async () => {
				for (const w of workflows) {
					try {
						const { fetch: run } = executeWorkflow({ id: w.id })
						await run()
					} catch (_) {}
				}
			},
		})
	}

	confirm(async (close) => {
		try {
			openLoad()
			// useForm 的 fetch 返回类型按表单值推导，但运行时返回 request 的结果，需断言
			const result = (await fetch()) as unknown as UpdateCertResult | undefined
			// 新证书未覆盖原证书域名：提示缺失域名，确认后带 force 重新提交
			if (result?.needsConfirmation) {
				closeLoad()
				const list = result.uncoveredDomains.join('、')
				useDialog({
					title: '证书域名覆盖警告',
					content: `新证书未覆盖原证书的以下域名：${list}。继续更新可能导致相关服务的证书失效，是否仍要更新？`,
					confirmText: '仍要更新',
					cancelText: '取消',
					onPositiveClick: async () => {
						try {
							openLoad()
							const forced = await updateExistingCert({
								id: cert.id.toString(),
								cert: editForm.value.cert,
								key: editForm.value.key,
								force: true,
							})
							close()
							if (!forced.needsConfirmation) showWorkflowDialog(forced.associatedWorkflows)
						} catch (_) {
							// API error already displayed by handleApiError in useAxios; modal stays open
						} finally {
							closeLoad()
						}
					},
				})
				return
			}
			close()
			if (result && !result.needsConfirmation) showWorkflowDialog(result.associatedWorkflows)
		} catch (_) {
			// API error already displayed by handleApiError in useAxios; modal stays open
		} finally {
			closeLoad()
		}
	})

	return {
		EditCertForm: component,
	}
}
