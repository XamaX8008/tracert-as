from traceroute import Traceroute
from prepare_args import prepare_args

if __name__ == '__main__':
    args = prepare_args()
    traceroute = Traceroute(args.hostname, args.ttl)
    trace_result = traceroute.make_trace()
    for i in range(len(trace_result)):
        if trace_result[i] is None:
            print(f"{i + 1}. *")
        else:
            print(f"{i + 1}. {trace_result[i]}")
