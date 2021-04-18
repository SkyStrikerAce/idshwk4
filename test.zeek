@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) 
{
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) 
    {
        SumStats::observe("response_404", 
    					  SumStats::Key($host=c$id$orig_h), 
    					  SumStats::Observation($num=1));
        SumStats::observe("response_404_unique", 
                          SumStats::Key($host=c$id$orig_h), 
                          SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init() 
{
    local rp_all = SumStats::Reducer($stream="response", 
                                     $apply=set(SumStats::SUM));
    local rp_404 = SumStats::Reducer($stream="response_404", 
                                     $apply=set(SumStats::SUM));
    local rp_404_unq = SumStats::Reducer($stream="response_404_unique", 
                                         $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="httpscan_rp_404", 
                     $epoch=10min, 
                     $reducers=set(rp_all, rp_404, rp_404_unq), 
                     $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
                     {
                    	local r1 = result["response"];
                    	local r2 = result["response_404"];
                    	local r3 = result["response_404_unique"];
                    	if (r2$sum > 2) 
                    	{
                    		if (r2$sum / r1$sum > 0.2) 
                    		{
                    			if (r3$unique / r2$sum > 0.5) 
                    			{
                    				print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, r2$sum, r3$unique);
                    			} 
                    		}
                    	}
                     }]);
}
