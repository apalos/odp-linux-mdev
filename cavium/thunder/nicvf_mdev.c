/*******************************************************************************
 *
 * Cavium nicvf ethernet driver
 * Copyright(c) 2018 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 ******************************************************************************/

#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/net_mdev.h>
#include <asm/cacheflush.h>

#include "nic.h"
#include "nicvf_queues.h"

static void nicvf_destroy_vdev(struct mdev_device *mdev);

/* FIXME: last page can be left in cache with certain start/end combinations */
static nicvf_evict_dcache_range(void *start, void *end)
{
	void *ptr = start;

	while (ptr < end) {
		flush_dcache_page(virt_to_page(ptr));
		ptr += PAGE_SIZE;
	}
}

static int nicvf_init_vdev(struct mdev_device *mdev)
{
	struct netmdev *netmdev = mdev_get_drvdata(mdev);
	struct net_device *netdev = mdev_get_netdev(mdev);
	struct nicvf *nic = netdev_priv(netdev);
	struct pci_dev *pdev = nic->pdev;
	struct mdev_net_region *region;
	struct queue_set *qs = nic->qs;
	int i;
	int alloc_regions;
	phys_addr_t start;
	u64 size, offset;
	int offset_cnt;

	netmdev->vdev.bus_regions = VFIO_PCI_NUM_REGIONS;
	netmdev->vdev.extra_regions = nic->qs->rbdr_cnt + nic->qs->sq_cnt +
		nic->qs->cq_cnt;
	alloc_regions = netmdev->vdev.extra_regions + 1;

	netmdev->vdev.bus_flags = VFIO_DEVICE_FLAGS_PCI;
	netmdev->vdev.num_irqs = 1;

	netmdev->vdev.regions = kcalloc(alloc_regions,
					sizeof(*netmdev->vdev.regions), GFP_KERNEL);
	if (!netmdev->vdev.regions)
		goto err;

	region = netmdev->vdev.regions;

	/* MMIO */
	start = pci_resource_start(pdev, VFIO_PCI_BAR0_REGION_INDEX);
	size = pci_resource_len(pdev, VFIO_PCI_BAR0_REGION_INDEX);
	offset = VFIO_PCI_INDEX_TO_OFFSET(VFIO_PCI_BAR0_REGION_INDEX);
	mdev_net_add_essential(region++, VFIO_NET_MDEV_MMIO, 0, offset,
			       start >> PAGE_SHIFT, size >> PAGE_SHIFT);

	offset_cnt = netmdev->vdev.bus_regions;

	/* RBDR */
	for (i = 0; i < nic->qs->rbdr_cnt; i++) {
		struct rbdr *rbdr = &nic->qs->rbdr[i];

		start = virt_to_phys(rbdr->dmem.base);
		size = PAGE_ALIGN(qs->rbdr_len * sizeof(struct rbdr_entry_t));

		/* Poison and cache evict the area */
		memset(rbdr->desc, 0xa5, size);
		nicvf_evict_dcache_range(rbdr->desc, rbdr->desc + size);

		/*
		 * Assure no one is going to access descs from kernel space
		 * to avoid cache aliasing issues.
		 */
		rbdr->desc = NULL;

		offset = VFIO_PCI_INDEX_TO_OFFSET(offset_cnt++);
		mdev_net_add_essential(region++, VFIO_NET_MDEV_RX_BUFFER_POOL, 0,
				       offset,
				       start >> PAGE_SHIFT, size >> PAGE_SHIFT);
	}

	/* completion */
	for (i = 0; i < nic->qs->cq_cnt; i++) {
		struct cmp_queue *cq = &nic->qs->cq[i];

		start = virt_to_phys(cq->dmem.base);
		size = PAGE_ALIGN(qs->cq_len * CMP_QUEUE_DESC_SIZE);

		/* Poison and cache evict the area */
		memset(cq->desc, 0xa5, size);
		nicvf_evict_dcache_range(cq->desc, cq->desc + size);

		/*
		 * Assure no one is going to access descs from kernel space
		 * to avoid cache aliasing issues.
		 */
		cq->desc = NULL;

		offset = VFIO_PCI_INDEX_TO_OFFSET(offset_cnt++);
		mdev_net_add_essential(region++, VFIO_NET_MDEV_RX_RING, 0,
				       offset,
				       start >> PAGE_SHIFT, size >> PAGE_SHIFT);
	}

	/* Tx */
	for (i = 0; i < nic->qs->sq_cnt; i++) {
		struct snd_queue *sq = &nic->qs->sq[i];

		start = virt_to_phys(sq->dmem.base);
		size = PAGE_ALIGN(qs->sq_len * SND_QUEUE_DESC_SIZE);

		/* Poison and cache evict the area */
		memset(sq->desc, 0xa5, size);
		nicvf_evict_dcache_range(sq->desc, sq->desc + size);

		/*
		 * Assure no one is going to access descs from kernel space
		 * to avoid cache aliasing issues.
		 */
		sq->desc = NULL;

		offset = VFIO_PCI_INDEX_TO_OFFSET(offset_cnt++);
		mdev_net_add_essential(region++, VFIO_NET_MDEV_TX_RING, 0,
				       offset,
				       start >> PAGE_SHIFT, size >> PAGE_SHIFT);
	}

	netmdev->vdev.used_regions = region - netmdev->vdev.regions;
	BUG_ON(netmdev->vdev.used_regions != alloc_regions);

	return 0;

err:
	nicvf_destroy_vdev(mdev);
	return -EFAULT;
}

static void nicvf_destroy_vdev(struct mdev_device *mdev)
{
	struct netmdev *netmdev = mdev_get_drvdata(mdev);

	kfree(netmdev->vdev.regions);
}

static int nicvf_transition_start(struct mdev_device *mdev)
{
	struct net_device *netdev = mdev_get_netdev(mdev);

	dev_hold(netdev);

	if (nicvf_init_vdev(mdev)) {
		dev_put(netdev);
		return -EINVAL;
	}

	return 0;
}

static int nicvf_transition_back(struct mdev_device *mdev)
{
	struct net_device *netdev = mdev_get_netdev(mdev);

	nicvf_destroy_vdev(mdev);
	dev_put(netdev);

	return 0;
}

static struct netmdev_driver_ops nicvf_netmdev_driver_ops = {
	.transition_start = nicvf_transition_start,
	.transition_back = nicvf_transition_back,
};

void nicvf_register_netmdev(struct device *dev)
{
	int (*register_device)(struct device *d,
			       struct netmdev_driver_ops *ops);

	register_device = symbol_get(netmdev_register_device);
	if (!register_device)
		return;

	if (register_device(dev, &nicvf_netmdev_driver_ops) < 0)
		dev_err(dev, "Could not register device\n");
	else
		dev_info(dev, "Successfully registered net_mdev device\n");

	symbol_put(netmdev_register_device);
}

void nicvf_unregister_netmdev(struct device *dev)
{
	int (*unregister_device)(struct device *d);

	unregister_device = symbol_get(netmdev_unregister_device);
	if (!unregister_device)
		return;

	if (unregister_device(dev) < 0)
		dev_err(dev, "Could not unregister device\n");
	else
		dev_info(dev,
			 "Successfully unregistered net_mdev device\n");

	symbol_put(netmdev_unregister_device);
}
