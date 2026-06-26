import { Ref, computed, watch, onUnmounted } from 'vue'
import { defineComponent, PropType } from 'vue'
import { useNodeValidator } from '@components/FlowChart/lib/verify'
import { useStore } from '@components/FlowChart/useStore'
import { useThemeCssVar } from '@baota/naive-ui/theme'
import { $t } from '@locales/index'
import baseRules from './verify'
import Drawer from './model'
import { useNodeHandler } from '@workflowView/lib/NodeHandler'
import type { ApplyNodeConfig } from '@components/FlowChart/types'

interface NodeProps {
	node: {
		id: string
		config: ApplyNodeConfig
	}
}

export default defineComponent({
	name: 'ApplyNode',
	props: {
		node: {
			type: Object as PropType<{ id: string; config: ApplyNodeConfig }>,
			default: () => ({ id: '', config: {} }),
		},
	},
	setup(props: NodeProps, { expose }) {
		const { isRefreshNode } = useStore()
		const { registerCompatValidator, validate, validationResult, unregisterValidator } = useNodeValidator()
		const cssVar = useThemeCssVar(['warningColor', 'primaryColor'])

		const validColor = computed(() =>
			validationResult.value.valid ? 'var(--n-primary-color)' : 'var(--n-warning-color)',
		)

		// provider_id 在 dns-persist-01 时不必填，其余模式必填
		const buildRules = () => {
			const isDNSPersist = props.node.config.challenge_type === 'dns-persist-01'
			return {
				...baseRules,
				provider_id: isDNSPersist
					? { required: false, trigger: 'change' }
					: { required: true, message: $t('t_3_1745490735059'), trigger: 'change' },
			}
		}

		const revalidate = () => {
			registerCompatValidator(props.node.id, buildRules(), props.node.config)
			validate(props.node.id)
		}

		watch(
			() => isRefreshNode.value,
			() => {
				useTimeoutFn(revalidate, 500)
			},
			{ immediate: true },
		)

		// challenge_type 变更时立即重新验证
		watch(() => props.node.config.challenge_type, revalidate)

		onUnmounted(() => unregisterValidator(props.node.id))

		/**
		 * @description 渲染节点内容
		 * @param {boolean} valid 是否有效
		 * @param {ApplyNodeConfig} config 节点配置
		 * @returns {string} 渲染节点内容
		 */
		const renderContent = (valid: boolean, config: ApplyNodeConfig) => {
			if (valid) return $t('t_9_1747817611448') + config?.domains
			return $t('t_9_1745735765287')
		}

		const renderNode = () => (
			<div style={cssVar.value} class="text-[12px]">
				<div style={{ color: validColor.value }}>{renderContent(validationResult.value.valid, props.node.config)}</div>
			</div>
		)

		// 使用通用节点处理器
		const { handleNodeClick } = useNodeHandler<ApplyNodeConfig>()

		// 暴露方法给父组件
		expose({
			handleNodeClick: (selectedNode: Ref<{ id: string; name: string; config: ApplyNodeConfig }>) =>
				handleNodeClick(selectedNode, (node) => <Drawer node={node} />),
		})

		return renderNode
	},
})
