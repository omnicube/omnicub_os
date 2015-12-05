#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/stat.h>

#include "nvmet.h"


CONFIGFS_ATTR_STRUCT(nvmet_ns);
CONFIGFS_ATTR_OPS(nvmet_ns);

static ssize_t nvmet_ns_device_path_show(struct nvmet_ns *ns, char *page)
{
	return sprintf(page, "%s", ns->device_path);
}

static ssize_t nvmet_ns_device_path_store(struct nvmet_ns *ns, const char *page,
		size_t count)
{
	int ret = nvmet_ns_enable(ns, page);

	return ret ? ret : count;
}

static struct nvmet_ns_attribute nvmet_ns_attr_device_path = {
	.attr = {
		.ca_name	= "device_path",
		.ca_mode	= S_IRUSR | S_IWUSR,
		.ca_owner	= THIS_MODULE,
	},
	.show			= nvmet_ns_device_path_show,
	.store			= nvmet_ns_device_path_store,
};

static struct configfs_attribute *nvmet_ns_attrs[] = {
	&nvmet_ns_attr_device_path.attr,
	NULL,
};

static void nvmet_ns_release(struct config_item *item)
{
	struct nvmet_ns *ns = to_nvmet_ns(item);

	nvmet_ns_free(ns);
}

static struct configfs_item_operations nvmet_ns_item_ops = {
	.release		= nvmet_ns_release,
	.show_attribute		= nvmet_ns_attr_show,
	.store_attribute        = nvmet_ns_attr_store,
};

static struct config_item_type nvmet_ns_type = {
	.ct_item_ops		= &nvmet_ns_item_ops,
	.ct_attrs		= nvmet_ns_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *nvmet_ns_make(struct config_group *group,
		const char *name)
{
	struct nvmet_subsys *subsys = namespaces_to_subsys(&group->cg_item);
	struct nvmet_ns *ns;
	int ret;
	u32 nsid;

	ret = kstrtou32(name, 0, &nsid);
	if (ret)
		goto out;

	ret = -EINVAL;
	if (nsid == 0 || nsid == 0xffffffff)
		goto out;

	ret = -ENOMEM;
	ns = nvmet_ns_alloc(subsys, nsid);
	if (!ns)
		goto out;
	config_group_init_type_name(&ns->group, name, &nvmet_ns_type);

	pr_info("adding nsid %d to subsystem %s\n", nsid, subsys->subsys_name);

	return &ns->group;
out:
	return ERR_PTR(ret);
}

static struct configfs_group_operations nvmet_namespaces_group_ops = {
	.make_group		= nvmet_ns_make,
};

static struct config_item_type nvmet_namespaces_type = {
	.ct_group_ops		= &nvmet_namespaces_group_ops,
	.ct_owner		= THIS_MODULE,
};

static struct config_item_type nvmet_controllers_type = {
	.ct_owner		= THIS_MODULE,
};

static void nvmet_subsys_release(struct config_item *item)
{
	struct nvmet_subsys *subsys = to_subsys(item);

	nvmet_subsys_free(subsys);
}

static struct configfs_item_operations nvmet_subsys_item_ops = {
	.release		= nvmet_subsys_release,
};

static struct config_item_type nvmet_subsys_type = {
	.ct_item_ops		= &nvmet_subsys_item_ops,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *nvmet_subsys_make(struct config_group *group,
		const char *name)
{
	struct nvmet_subsys *subsys;

	subsys = nvmet_subsys_alloc(name);
	if (!subsys)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&subsys->group, name, &nvmet_subsys_type);

	config_group_init_type_name(&subsys->namespaces_group,
			"namespaces", &nvmet_namespaces_type);
	config_group_init_type_name(&subsys->controllers_group,
			"controllers", &nvmet_controllers_type);

	subsys->default_groups[0] = &subsys->namespaces_group;
	subsys->default_groups[1] = &subsys->controllers_group;
	subsys->default_groups[2] = NULL;

	subsys->group.default_groups = subsys->default_groups;
	return &subsys->group;
}

static struct configfs_group_operations nvmet_subsystems_group_ops = {
	.make_group		= nvmet_subsys_make,
};

static struct config_item_type nvmet_subsystems_type = {
	.ct_group_ops		= &nvmet_subsystems_group_ops,
	.ct_owner		= THIS_MODULE,
};

struct config_group nvmet_subsystems_group;

struct config_group *nvmet_root_default_groups[] = {
	&nvmet_subsystems_group,
	NULL,
};

static struct config_item_type nvmet_root_type = {
	.ct_owner		= THIS_MODULE,
};

static struct configfs_subsystem nvmet_configfs_subsystem = {
	.su_group = {
		.cg_item = {
			.ci_namebuf	= "nvmet",
			.ci_type	= &nvmet_root_type,
		},
		.default_groups = nvmet_root_default_groups,
	},
};

int __init nvmet_init_configfs(void)
{
	int ret;

	config_group_init(&nvmet_configfs_subsystem.su_group);
	mutex_init(&nvmet_configfs_subsystem.su_mutex);

	config_group_init_type_name(&nvmet_subsystems_group,
			"subsystems", &nvmet_subsystems_type);

	ret = configfs_register_subsystem(&nvmet_configfs_subsystem);
	if (ret) {
		pr_err("configfs_register_subsystem: %d\n", ret);
		return ret;
	}

	return 0;
}

void __exit nvmet_exit_configfs(void)
{
	configfs_unregister_subsystem(&nvmet_configfs_subsystem);
}

