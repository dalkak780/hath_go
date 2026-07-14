/*

Copyright 2008-2026 E-Hentai.org
https://forums.e-hentai.org/
tenboro@e-hentai.org

This file is part of Hentai@Home.

Hentai@Home is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hentai@Home is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Hentai@Home.  If not, see <https://www.gnu.org/licenses/>.

*/

package hath.base;

import java.lang.Thread;

public class CachePruner implements Runnable {
	private Thread myThread;
	private CacheHandler cacheHandler;
	private HentaiAtHomeClient client;
	private int checkFrequency = 60;

	public CachePruner(CacheHandler cacheHandler, HentaiAtHomeClient client) {
		this.cacheHandler = cacheHandler;
		this.client = client;

		myThread = new Thread(this);
		myThread.start();
	}

	public void setCheckFrequency(int checkFrequency) {
		this.checkFrequency = checkFrequency;
	}

	public void run() {
		java.text.DecimalFormat f = new java.text.DecimalFormat("###.000");
		int cacheCheckTicks = 0, diskCheckTicks = 0;

		do {
			long cacheLimit = Settings.getDiskLimitBytes();
			long cacheSize = cacheHandler.getCacheSizeWithOverhead();

			if(cacheSize > cacheLimit) {
				Out.info("CacheHandler: Cache is currently " + f.format((100.0 * cacheSize / cacheLimit) - 100.0) + "% over the limit, aggressively pruning until the limit is met");
				cacheHandler.checkAndPruneCache();
			}
			else {
				if(++cacheCheckTicks > checkFrequency) {
					cacheHandler.checkAndPruneCache();
					cacheCheckTicks = 0;
				}

				if(++diskCheckTicks > 300) {
					if(!cacheHandler.hasFreeDiskSpace()) {
						// disk is full and it's not on us. time to shut down so we don't add to the damage.
						client.dieWithError("The free disk space has dropped below the minimum allowed threshold. H@H cannot safely continue.\nFree up space for H@H, or reduce the cache size from the H@H settings page:\nhttps://e-hentai.org/hentaiathome.php?cid=" + Settings.getClientID());
					}
					
					diskCheckTicks = 0;
				}
			}

			try {
				myThread.sleep(1000);
			} catch(java.lang.InterruptedException e) {}
		} while(!client.isShuttingDown());

		Out.debug("CacheHandler: Pruner thread exited due to client shutdown");
	}
}
