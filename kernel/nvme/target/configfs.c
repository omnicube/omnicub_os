/*
 * Copyright (c) 2015 HGST, a Western Digital Company.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/ctype.h>

#include "nvmet.h"

/*
 * nvmet_addr Generic ConfigFS definitions.
 * Used in any place in the ConfigFS tree that refers to an address.
 */
static ssize_t nvmet_addr_enable_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%d\n",
		nvmet_addr_enabled(to_nvmet_addr(item)));
}

static ssize_t nvmet_addr_enable_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);
	bool enable;
	int ret = 0;

	if (strtobool(page, &enable))
		goto inval;

	if (enable == nvmet_addr_enabled(addr))
		return count;

	if (enable)
		ret = nvmet_enable_port(addr);
	else
		nvmet_disable_port(addr);

	return ret ? ret : count;
inval:
	pr_err("Invalid value '%s' for enable\n", page);
	return -EINVAL;
}

CONFIGFS_ATTR(nvmet_addr_, enable);

static ssize_t nvmet_addr_adrfam_show(struct config_item *item,
		char *page)
{
	switch (to_nvmet_addr(item)->disc_addr.adrfam) {
	case NVMF_ADDR_FAMILY_IP4:
		return sprintf(page, "ipv4\n");
	case NVMF_ADDR_FAMILY_IP6:
		return sprintf(page, "ipv6\n");
	case NVMF_ADDR_FAMILY_IB:
		return sprintf(page, "ib\n");
	default:
		return sprintf(page, "\n");
	}
}

static ssize_t nvmet_addr_adrfam_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}

	if (sysfs_streq(page, "ipv4")) {
		addr->disc_addr.adrfam = NVMF_ADDR_FAMILY_IP4;
	} else if (sysfs_streq(page, "ipv6")) {
		addr->disc_addr.adrfam = NVMF_ADDR_FAMILY_IP6;
	} else if (sysfs_streq(page, "ib")) {
		addr->disc_addr.adrfam = NVMF_ADDR_FAMILY_IB;
	} else {
		pr_err("Invalid value '%s' for adrfam\n", page);
		return -EINVAL;
	}

	return count;
}

CONFIGFS_ATTR(nvmet_, addr_adrfam);

static ssize_t nvmet_addr_portid_show(struct config_item *item,
		char *page)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	return snprintf(page, PAGE_SIZE, "%d\n",
			le16_to_cpu(addr->disc_addr.portid));
}

static ssize_t nvmet_addr_portid_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);
	u16 portid = 0;

	if (kstrtou16(page, 0, &portid)) {
		pr_err("Invalid value '%s' for portid\n", page);
		return -EINVAL;
	}

	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}
	addr->disc_addr.portid = cpu_to_le16(portid);
	return count;
}

CONFIGFS_ATTR(nvmet_, addr_portid);

static ssize_t nvmet_addr_traddr_show(struct config_item *item,
		char *page)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	return snprintf(page, PAGE_SIZE, "%s\n",
			addr->disc_addr.traddr);
}

static ssize_t nvmet_addr_traddr_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	if (count > NVMF_TRADDR_SIZE) {
		pr_err("Invalid value '%s' for traddr\n", page);
		return -EINVAL;
	}

	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}
	return snprintf(addr->disc_addr.traddr,
			sizeof(addr->disc_addr.traddr), "%s", page);
}

CONFIGFS_ATTR(nvmet_, addr_traddr);

static ssize_t nvmet_addr_treq_show(struct config_item *item,
		char *page)
{
	switch (to_nvmet_addr(item)->disc_addr.treq) {
	case NVMF_TREQ_NOT_SPECIFIED:
		return sprintf(page, "not specified\n");
	case NVMF_TREQ_REQUIRED:
		return sprintf(page, "required\n");
	case NVMF_TREQ_NOT_REQUIRED:
		return sprintf(page, "not required\n");
	default:
		return sprintf(page, "\n");
	}
}

static ssize_t nvmet_addr_treq_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}

	if (sysfs_streq(page, "not specified")) {
		addr->disc_addr.treq = NVMF_TREQ_NOT_SPECIFIED;
	} else if (sysfs_streq(page, "required")) {
		addr->disc_addr.treq = NVMF_TREQ_REQUIRED;
	} else if (sysfs_streq(page, "not required")) {
		addr->disc_addr.treq = NVMF_TREQ_NOT_REQUIRED;
	} else {
		pr_err("Invalid value '%s' for treq\n", page);
		return -EINVAL;
	}

	return count;
}

CONFIGFS_ATTR(nvmet_, addr_treq);

static ssize_t nvmet_addr_trsvcid_show(struct config_item *item,
		char *page)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	return snprintf(page, PAGE_SIZE, "%s\n",
			addr->disc_addr.trsvcid);
}

static ssize_t nvmet_addr_trsvcid_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	if (count > NVMF_TRSVCID_SIZE) {
		pr_err("Invalid value '%s' for trsvcid\n", page);
		return -EINVAL;
	}
	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}
	return snprintf(addr->disc_addr.trsvcid,
			sizeof(addr->disc_addr.trsvcid), "%s", page);
}

CONFIGFS_ATTR(nvmet_, addr_trsvcid);

static ssize_t nvmet_addr_trtype_show(struct config_item *item,
		char *page)
{
	switch (to_nvmet_addr(item)->disc_addr.trtype) {
	case NVMF_TRTYPE_RDMA:
		return sprintf(page, "rdma\n");
	default:
		return sprintf(page, "\n");
	}
}

static void nvmet_addr_init_tsas_rdma(struct nvmet_addr *addr)
{
	addr->disc_addr.trtype = NVMF_TRTYPE_RDMA;
	memset(&addr->disc_addr.tsas.rdma, 0, NVMF_TSAS_SIZE);
	addr->disc_addr.tsas.rdma.qptype = NVMF_RDMA_QPTYPE_CONNECTED;
	addr->disc_addr.tsas.rdma.prtype = NVMF_RDMA_PRTYPE_NOT_SPECIFIED;
	addr->disc_addr.tsas.rdma.cms = NVMF_RDMA_CMS_RDMA_CM;
}

static ssize_t nvmet_addr_trtype_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	if (nvmet_addr_enabled(addr)) {
		pr_err("Cannot modify address while enabled\n");
		pr_err("Disable the address before modifying\n");
		return -EACCES;
	}

	if (sysfs_streq(page, "rdma")) {
		nvmet_addr_init_tsas_rdma(addr);
	} else {
		pr_err("Invalid value '%s' for trtype\n", page);
		return -EINVAL;
	}

	return count;
}

CONFIGFS_ATTR(nvmet_, addr_trtype);

/*
 * Namespace structures & file operation functions below
 */
static ssize_t nvmet_ns_device_path_show(struct config_item *item, char *page)
{
	return sprintf(page, "%s", to_nvmet_ns(item)->device_path);
}

static ssize_t nvmet_ns_device_path_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_ns *ns = to_nvmet_ns(item);
	struct nvmet_subsys *subsys = ns->subsys;
	int ret;

	mutex_lock(&subsys->lock);
	ret = -EBUSY;
	if (nvmet_ns_enabled(ns))
		goto out_unlock;

	kfree(ns->device_path);

	ret = -ENOMEM;
	ns->device_path = kstrdup(page, GFP_KERNEL);
	if (!ns->device_path)
		goto out_unlock;

	mutex_unlock(&subsys->lock);
	return count;

out_unlock:
	mutex_unlock(&subsys->lock);
	return ret;
}

CONFIGFS_ATTR(nvmet_ns_, device_path);

static ssize_t nvmet_ns_device_nguid_show(struct config_item *item, char *page)
{
	return sprintf(page, "%pUb\n", &to_nvmet_ns(item)->nguid);
}

static ssize_t nvmet_ns_device_nguid_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_ns *ns = to_nvmet_ns(item);
	struct nvmet_subsys *subsys = ns->subsys;
	u8 nguid[16];
	const char *p = page;
	int i;
	int ret;

	mutex_lock(&subsys->lock);
	if (nvmet_ns_enabled(ns)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	for (i = 0; i < 16; i++) {
		if (p + 2 > page + count)
			return -EINVAL;
		if (!isxdigit(p[0]) || !isxdigit(p[1]))
			return -EINVAL;


		nguid[i] = (hex_to_bin(p[0]) << 4) | hex_to_bin(p[1]);
		p += 2;

		if (*p == '-' || *p == ':')
			p++;
	}

	memcpy(&ns->nguid, nguid, sizeof(nguid));
out_unlock:
	mutex_unlock(&subsys->lock);
	return ret ? ret : count;
}

CONFIGFS_ATTR(nvmet_ns_, device_nguid);

static ssize_t nvmet_ns_enable_show(struct config_item *item, char *page)
{
	return sprintf(page, "%d", nvmet_ns_enabled(to_nvmet_ns(item)));
}

static ssize_t nvmet_ns_enable_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_ns *ns = to_nvmet_ns(item);
	bool enable;
	int ret = 0;

	if (strtobool(page, &enable))
		return -EINVAL;

	if (enable)
		ret = nvmet_ns_enable(ns);
	else
		nvmet_ns_disable(ns);

	return ret ? ret : count;
}

CONFIGFS_ATTR(nvmet_ns_, enable);

static struct configfs_attribute *nvmet_ns_attrs[] = {
	&nvmet_ns_attr_device_path,
	&nvmet_ns_attr_device_nguid,
	&nvmet_ns_attr_enable,
	NULL,
};

static void nvmet_ns_release(struct config_item *item)
{
	struct nvmet_ns *ns = to_nvmet_ns(item);

	nvmet_ns_free(ns);
}

static struct configfs_item_operations nvmet_ns_item_ops = {
	.release		= nvmet_ns_release,
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

/*
 * Subsystem structures & folder operation functions below
 */
static void nvmet_subsys_release(struct config_item *item)
{
	struct nvmet_subsys *subsys = to_subsys(item);

	nvmet_subsys_put(subsys);
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

	if (sysfs_streq(name, NVME_DISC_SUBSYS_NAME)) {
		pr_err("can't create discovery subsystem through configfs\n");
		return ERR_PTR(-EINVAL);
	}

	subsys = nvmet_subsys_alloc(name, NVME_NQN_NVME);
	if (!subsys)
		return ERR_PTR(-ENOMEM);

	config_group_init_type_name(&subsys->group, name, &nvmet_subsys_type);

	config_group_init_type_name(&subsys->namespaces_group,
			"namespaces", &nvmet_namespaces_type);

	subsys->default_groups[0] = &subsys->namespaces_group;
	subsys->default_groups[1] = NULL;

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

static ssize_t nvmet_ref_addr_enable_show(struct config_item *item,
		char *page)
{
	return snprintf(page, PAGE_SIZE, "%d\n",
		nvmet_addr_enabled(to_nvmet_addr(item)));
}

static ssize_t nvmet_ref_addr_enable_store(struct config_item *item,
		const char *page, size_t count)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);
	bool enable;

	if (strtobool(page, &enable))
		goto inval;

	if (enable)
		nvmet_ref_addr_enable(addr);
	else
		nvmet_ref_addr_disable(addr);

	return count;
inval:
	pr_err("Invalid value '%s' for enable\n", page);
	return -EINVAL;
}

CONFIGFS_ATTR(nvmet_ref_addr_, enable);

/*
 * Discovery Service subsystem definitions
 */
static struct configfs_attribute *nvmet_ref_addr_attrs[] = {
	&nvmet_attr_addr_adrfam,
	&nvmet_attr_addr_portid,
	&nvmet_attr_addr_treq,
	&nvmet_attr_addr_traddr,
	&nvmet_attr_addr_trsvcid,
	&nvmet_attr_addr_trtype,
	&nvmet_ref_addr_attr_enable,
	NULL,
};

static void nvmet_referral_addr_release(struct config_item *item)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	nvmet_ref_addr_disable(addr);
	kfree(addr);
}

static struct configfs_item_operations nvmet_ref_addr_item_ops = {
	.release	= nvmet_referral_addr_release,
};

static struct config_item_type nvmet_ref_addr_type = {
	.ct_owner	= THIS_MODULE,
	.ct_attrs	= nvmet_ref_addr_attrs,
	.ct_item_ops	= &nvmet_ref_addr_item_ops,
};

static struct config_group *nvmet_referral_addr_make(
		struct config_group *group, const char *name)
{
	struct nvmet_addr *addr;

	addr = kzalloc(sizeof(*addr), GFP_KERNEL);
	if (IS_ERR(addr))
		return ERR_CAST(addr);

	INIT_LIST_HEAD(&addr->entry);
	config_group_init_type_name(&addr->group, name,
			&nvmet_ref_addr_type);

	return &addr->group;
}

static struct configfs_group_operations nvmet_referral_addr_group_ops = {
	.make_group		= nvmet_referral_addr_make,
};

static struct config_item_type nvmet_referrals_type = {
	.ct_owner	= THIS_MODULE,
	.ct_group_ops	= &nvmet_referral_addr_group_ops,
};

static struct config_group nvmet_referrals_group;

/*
 * Ports definitions.
 */
static void nvmet_port_release(struct config_item *item)
{
	struct nvmet_addr *addr = to_nvmet_addr(item);

	nvmet_disable_port(addr);
	kfree(addr);
}

static struct configfs_attribute *nvmet_port_attrs[] = {
	&nvmet_attr_addr_adrfam,
	&nvmet_attr_addr_treq,
	&nvmet_attr_addr_traddr,
	&nvmet_attr_addr_trsvcid,
	&nvmet_attr_addr_trtype,
	&nvmet_addr_attr_enable,
	NULL,
};

static struct configfs_item_operations nvmet_port_item_ops = {
	.release		= nvmet_port_release,
};

static struct config_item_type nvmet_port_type = {
	.ct_attrs		= nvmet_port_attrs,
	.ct_item_ops		= &nvmet_port_item_ops,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *nvmet_ports_make(struct config_group *group,
		const char *name)
{
	struct nvmet_addr *addr;
	u16 portid;

	if (kstrtou16(name, 0, &portid))
		return ERR_PTR(-EINVAL);

	addr = kzalloc(sizeof(*addr), GFP_KERNEL);
	if (IS_ERR(addr))
		return ERR_CAST(addr);

	INIT_LIST_HEAD(&addr->entry);
	addr->disc_addr.portid = cpu_to_le16(portid);
	config_group_init_type_name(&addr->group, name, &nvmet_port_type);
	return &addr->group;
}

static struct configfs_group_operations nvmet_ports_group_ops = {
	.make_group		= nvmet_ports_make,
};

static struct config_item_type nvmet_ports_type = {
	.ct_group_ops		= &nvmet_ports_group_ops,
	.ct_owner		= THIS_MODULE,
};

static struct config_group nvmet_subsystems_group;
static struct config_group nvmet_ports_group;

static struct config_group *nvmet_root_default_groups[] = {
	&nvmet_subsystems_group,
	&nvmet_ports_group,
	&nvmet_referrals_group,
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

	config_group_init_type_name(&nvmet_referrals_group,
			"referrals", &nvmet_referrals_type);

	config_group_init_type_name(&nvmet_ports_group,
			"ports", &nvmet_ports_type);

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
